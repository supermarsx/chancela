//! XAdES sign→validate round-trip and ASiC-E multi-signature signing API tests (t67-e10).
//!
//! The PKCS#12 signer is generated in-process (no checked-in keys, no OS store, no network). The
//! endpoints are local/technical: they produce or validate a signature and persist nothing.

mod common;

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

use common::{TEST_PASSWORD, password_hash};

const PASSWORD: &str = "correct horse battery staple";
const FRIENDLY_NAME: &str = "xades signing identity";
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
            display_name: "XAdES Signer".to_owned(),
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

/// Build an RSA PKCS#12 (PFX) with a self-signed leaf. Distinct `serial` values yield distinct
/// signer certificates for multi-signature containers.
fn build_pfx(cn: &str, serial: u8) -> Vec<u8> {
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("rsa keygen");
    let spki =
        SubjectPublicKeyInfoOwned::from_key(rsa::RsaPublicKey::from(&key)).expect("rsa spki");
    let cert = build_self_signed(cn, serial, spki);
    let key_der = key.to_pkcs8_der().expect("rsa pkcs8");
    p12::PFX::new(&cert, key_der.as_bytes(), None, PASSWORD, FRIENDLY_NAME)
        .expect("pfx")
        .to_der()
}

fn signer_json(pfx: &[u8]) -> Value {
    json!({
        "kind": "soft_pkcs12",
        "pkcs12_base64": B64.encode(pfx),
        "passphrase": PASSWORD,
        "friendly_name": FRIENDLY_NAME,
    })
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
async fn xades_detached_sign_then_validate_round_trip() {
    let (state, token) = local_state().await;
    let pfx = build_pfx("XAdES Detached Signer", 1);
    let content = b"deliberation minutes payload";

    let (status, signed) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/sign",
            &token,
            json!({
                "content_base64": B64.encode(content),
                "content_name": "minutes.txt",
                "packaging": "detached",
                "level": "B",
                "signer": signer_json(&pfx),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "xades sign: {signed}");
    assert_eq!(signed["level"], "XAdES-B");
    assert_eq!(signed["packaging"], "detached");
    assert_eq!(signed["signature_algorithm"], "rsa-sha256");
    let xades_b64 = signed["xades_base64"].as_str().expect("xades_base64");

    let (status, report) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/validate",
            &token,
            json!({ "xades_base64": xades_b64 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "xades validate: {report}");
    let r = &report["report"];
    assert_eq!(r["signature_valid"], true, "{report}");
    assert_eq!(r["references_valid"], true);
    assert_eq!(r["signed_properties_present"], true);
    assert_eq!(r["signing_certificate_v2_present"], true);
    assert_eq!(r["is_valid_b"], true);
    assert_eq!(r["level"], "XAdES-B");
}

#[tokio::test]
async fn xades_enveloping_sign_then_validate_checks_object_reference() {
    let (state, token) = local_state().await;
    let pfx = build_pfx("XAdES Enveloping Signer", 2);

    let (status, signed) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/sign",
            &token,
            json!({
                "content_base64": B64.encode(b"enveloped data object"),
                "packaging": "enveloping",
                "signer": signer_json(&pfx),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "xades enveloping sign: {signed}");
    assert_eq!(signed["packaging"], "enveloping");
    let xades_b64 = signed["xades_base64"].as_str().expect("xades_base64");

    let (status, report) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/validate",
            &token,
            json!({ "xades_base64": xades_b64 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "validate: {report}");
    let r = &report["report"];
    assert_eq!(r["is_valid_b"], true, "{report}");
    // The enveloping object (#content) is a same-document reference, so it is checkable: at least
    // the object + SignedProperties references were dereferenced and matched.
    assert!(
        r["references_checked"].as_u64().unwrap() >= 2,
        "expected the object and signed-properties references to be checked: {report}"
    );
}

#[tokio::test]
async fn xades_sign_requires_co_location() {
    // Default AppState has local_signing = false.
    let state = AppState::default();
    let token = owner_session(&state).await;
    let pfx = build_pfx("XAdES No Colocation", 3);

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/sign",
            &token,
            json!({
                "content_base64": B64.encode(b"x"),
                "signer": signer_json(&pfx),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test]
async fn xades_validate_rejects_tampered_signature() {
    let (state, token) = local_state().await;
    let pfx = build_pfx("XAdES Tamper", 4);

    let (status, signed) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/sign",
            &token,
            json!({
                "content_base64": B64.encode(b"original"),
                "packaging": "enveloping",
                "signer": signer_json(&pfx),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sign: {signed}");
    let xades_b64 = signed["xades_base64"].as_str().unwrap();
    let mut xml = B64.decode(xades_b64).unwrap();
    // Corrupt the enveloped object content so the digest no longer matches.
    let needle = b"enveloped";
    if let Some(pos) = xml.windows(needle.len()).position(|w| w == needle) {
        xml[pos] = b'X';
    } else {
        // The object text differs; flip a byte in the middle of the document instead.
        let mid = xml.len() / 2;
        xml[mid] ^= 0xff;
    }

    let (status, report) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/xades/validate",
            &token,
            json!({ "xades_base64": B64.encode(&xml) }),
        ),
    )
    .await;
    // Either the tamper breaks XML well-formedness (422) or the validator reports it invalid (200).
    if status == StatusCode::OK {
        let r = &report["report"];
        assert!(
            r["signature_valid"] == false
                || r["references_valid"] == false
                || r["is_valid_b"] == false,
            "tampered document must not validate clean: {report}"
        );
    } else {
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{report}");
    }
}

#[tokio::test]
async fn asic_e_multi_signature_signs_and_validates() {
    let (state, token) = local_state().await;
    let cades_pfx = build_pfx("ASiC CAdES Signer", 5);
    let xades_pfx = build_pfx("ASiC XAdES Signer", 6);

    let (status, signed) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/asic/sign",
            &token,
            json!({
                "container": "asic_e_multi",
                "payloads": [
                    { "name": "act.txt", "content_base64": B64.encode(b"act payload bytes") },
                    { "name": "annex.txt", "content_base64": B64.encode(b"annex payload bytes") },
                ],
                "signers": [
                    { "role": "cades", "kind": "soft_pkcs12", "pkcs12_base64": B64.encode(&cades_pfx), "passphrase": PASSWORD, "friendly_name": FRIENDLY_NAME },
                    { "role": "xades", "kind": "soft_pkcs12", "pkcs12_base64": B64.encode(&xades_pfx), "passphrase": PASSWORD, "friendly_name": FRIENDLY_NAME },
                ],
                "xades_level": "B",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "asic-e sign: {signed}");
    assert_eq!(signed["container"], "ASiC-E");
    assert_eq!(signed["payload_count"], 2);
    assert_eq!(signed["cades_signature_count"], 1);
    assert_eq!(signed["xades_signature_count"], 1);

    // Validate the produced container through the signing-crate library surface (the ASiC-validation
    // HTTP endpoint is served elsewhere; here we prove the container is well-formed and both
    // signatures verify).
    let container = B64
        .decode(signed["asic_base64"].as_str().expect("asic_base64"))
        .expect("asic bytes");
    let report =
        chancela_signing::validate_asic_container(&container).expect("validate asic container");
    assert!(
        report.signatures.len() >= 2,
        "expected the CAdES and XAdES signatures to be found: {:?}",
        report.signatures.len()
    );
    assert!(
        report.signatures.iter().all(|s| s.valid),
        "every ASiC signature must verify"
    );
}

#[tokio::test]
async fn asic_s_xades_signs_single_payload() {
    let (state, token) = local_state().await;
    let pfx = build_pfx("ASiC-S XAdES Signer", 7);

    let (status, signed) = send(
        &state,
        json_req(
            "POST",
            "/v1/signature/asic/sign",
            &token,
            json!({
                "container": "asic_s_xades",
                "payloads": [ { "name": "doc.txt", "content_base64": B64.encode(b"single payload") } ],
                "signers": [
                    { "kind": "soft_pkcs12", "pkcs12_base64": B64.encode(&pfx), "passphrase": PASSWORD, "friendly_name": FRIENDLY_NAME },
                ],
                "xades_level": "B",
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "asic-s sign: {signed}");
    assert_eq!(signed["container"], "ASiC-S");
    assert_eq!(signed["xades_signature_count"], 1);

    let container = B64
        .decode(signed["asic_base64"].as_str().expect("asic_base64"))
        .expect("asic bytes");
    let report =
        chancela_signing::validate_asic_container(&container).expect("validate asic-s container");
    assert!(
        report.signatures.iter().all(|s| s.valid),
        "the ASiC-S XAdES signature must verify: {report:?}"
    );
}
