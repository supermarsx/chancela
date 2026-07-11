use std::io::Write;
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
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use chancela_api::{AppState, User, UserId, router};
use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, RoleCatalog, Scope};
use chancela_signing::asic::ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES;
use chancela_signing::{
    ASICE_CADES_SIGNATURE_PATH, ASICE_MANIFEST_PATH, ASICE_MIMETYPE, ASICS_CADES_SIGNATURE_PATH,
    ASICS_MIMETYPE, AsicPayload, EvidentiaryLevel, MockProvider, SignatureAlgorithm, SigningFamily,
    build_asic_e_manifest, sha256_content_digest, sign_asic_e, sign_asic_s, sign_detached_cades,
};

const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

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

    fn cert_der(&self) -> Vec<u8> {
        self.cert.to_der().expect("cert der")
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

fn provider(serial: u8) -> MockProvider {
    let signer = RsaSigner::new("ASiC inspection test signer", serial);
    let key = signer.key.clone();
    MockProvider::new(
        SigningFamily::QualifiedCertificate,
        EvidentiaryLevel::Advanced,
        SignatureAlgorithm::RsaPkcs1Sha256,
        signer.cert_der(),
        move |digest| Ok(sign_rsa_digest_info(&key, digest)),
    )
}

fn signing_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed signing time")
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

fn seeded_state() -> AppState {
    AppState {
        roles: Arc::new(RwLock::new(RoleCatalog::seeded_defaults())),
        ..AppState::default()
    }
}

async fn owner_session(state: &AppState) -> String {
    let uid = UserId(Uuid::new_v4());
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("created_at");
    state.users.write().await.insert(
        uid,
        User {
            id: uid,
            username: format!("asic-user-{}", uid.0),
            display_name: "ASiC Inspector".to_owned(),
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

fn post_asic(token: &str, container: &[u8]) -> Request<Body> {
    post_asic_body(
        token,
        json!({
            "asic_base64": B64.encode(container),
            "filename": "sample.asice",
            "declared_sha256": sha256_hex(container),
            "declared_size_bytes": container.len()
        }),
    )
}

fn post_asic_body(token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/signature/asic/inspect")
        .header("content-type", "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
        .expect("request builds")
}

fn zip_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (path, bytes) in entries {
        zip.start_file(*path, options).expect("zip member");
        zip.write_all(bytes).expect("zip write");
    }
    zip.finish().expect("zip finish").into_inner()
}

fn compressed_oversized_member_container() -> Vec<u8> {
    let payload = vec![0u8; ASIC_ZIP_MEMBER_UNCOMPRESSED_MAX_BYTES as usize + 1];
    let stored = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let deflated = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default());
    let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("mimetype", stored).expect("mimetype");
    zip.write_all(ASICS_MIMETYPE.as_bytes())
        .expect("write mimetype");
    zip.start_file("payload.txt", deflated).expect("payload");
    zip.write_all(&payload).expect("write payload");
    zip.start_file(ASICS_CADES_SIGNATURE_PATH, deflated)
        .expect("signature");
    zip.write_all(b"not-a-cades").expect("write signature");
    zip.finish().expect("zip finish").into_inner()
}

fn signed_asic_e_parts(serial: u8) -> (Vec<u8>, Vec<u8>) {
    let payloads = [AsicPayload {
        name: "a.txt",
        bytes: b"alpha",
        mime_type: Some("text/plain"),
    }];
    let manifest = build_asic_e_manifest(&payloads, ASICE_CADES_SIGNATURE_PATH).expect("manifest");
    let digest = sha256_content_digest(&manifest);
    let provider = provider(serial);
    let cades = sign_detached_cades(&provider, &digest, signing_time()).expect("cades");
    (manifest, cades)
}

fn asic_s_xades_container() -> Vec<u8> {
    zip_entries(&[
        ("mimetype", ASICS_MIMETYPE.as_bytes()),
        ("payload.txt", b"payload"),
        ("META-INF/signatures.xml", b"<ds:Signature/>"),
    ])
}

fn asic_e_xades_container() -> Vec<u8> {
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("payload.txt", b"payload"),
        ("META-INF/signatures.xml", b"<ds:Signature/>"),
    ])
}

fn asic_e_multiple_manifests_container() -> Vec<u8> {
    let (manifest, cades) = signed_asic_e_parts(21);
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("a.txt", b"alpha"),
        (ASICE_MANIFEST_PATH, &manifest),
        ("META-INF/ASiCManifest002.xml", &manifest),
        (ASICE_CADES_SIGNATURE_PATH, &cades),
    ])
}

fn asic_e_multiple_signatures_container() -> Vec<u8> {
    let (manifest, cades) = signed_asic_e_parts(22);
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("a.txt", b"alpha"),
        (ASICE_MANIFEST_PATH, &manifest),
        (ASICE_CADES_SIGNATURE_PATH, &cades),
        ("META-INF/signature002.p7s", &cades),
    ])
}

fn asic_e_missing_manifest_container() -> Vec<u8> {
    let (_manifest, cades) = signed_asic_e_parts(23);
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("a.txt", b"alpha"),
        (ASICE_CADES_SIGNATURE_PATH, &cades),
    ])
}

fn asic_e_digest_mismatch_container() -> Vec<u8> {
    let (manifest, cades) = signed_asic_e_parts(24);
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("a.txt", b"changed"),
        (ASICE_MANIFEST_PATH, &manifest),
        (ASICE_CADES_SIGNATURE_PATH, &cades),
    ])
}

fn asic_e_manifest_extensions_container() -> Vec<u8> {
    let digest = B64.encode(sha256_content_digest(b"alpha"));
    let manifest = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n\
  <asic:SigReference URI=\"{ASICE_CADES_SIGNATURE_PATH}\" MimeType=\"application/pkcs7-signature\"/>\n\
  <asic:ASiCManifestExtensions/>\n\
  <asic:DataObjectReference URI=\"a.txt\" MimeType=\"text/plain\">\n\
    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n\
    <ds:DigestValue>{digest}</ds:DigestValue>\n\
  </asic:DataObjectReference>\n\
</asic:ASiCManifest>\n"
    )
    .into_bytes();
    let provider = provider(25);
    let cades = sign_detached_cades(&provider, &sha256_content_digest(&manifest), signing_time())
        .expect("cades");
    zip_entries(&[
        ("mimetype", ASICE_MIMETYPE.as_bytes()),
        ("a.txt", b"alpha"),
        (ASICE_MANIFEST_PATH, &manifest),
        (ASICE_CADES_SIGNATURE_PATH, &cades),
    ])
}

fn unsafe_member_container() -> Vec<u8> {
    zip_entries(&[
        ("mimetype", ASICS_MIMETYPE.as_bytes()),
        ("../payload.txt", b"payload"),
        (ASICS_CADES_SIGNATURE_PATH, b"not-a-cades"),
    ])
}

fn assert_no_claim_boundaries(body: &Value) {
    assert_eq!(body["scope"], "local_technical_asic_cades_profile_evidence");
    assert_eq!(body["legal_validity_claimed"], false);
    assert_eq!(body["qualified_signature_claimed"], false);
    assert_eq!(body["trust_validation"], "not_performed");
    assert_eq!(body["revocation_validation"], "not_performed");
    assert_eq!(body["live_provider_calls"], false);
    assert_eq!(body["xades_validation_performed"], false);
    assert_eq!(body["b_lt_claimed"], false);
    assert_eq!(body["b_lta_claimed"], false);
    assert_eq!(body["production_asic_compliance_claimed"], false);
    assert_eq!(body["eidas_legal_effect_claimed"], false);
}

fn assert_cades_no_claim_boundaries(cades: &Value) {
    assert_eq!(cades["evidence_scope"], "technical_evidence_only");
    assert_eq!(cades["trust_validation"], "not_performed");
    assert_eq!(cades["revocation_validation"], "not_performed");
    assert_eq!(cades["legal_validity_claimed"], false);
    assert_eq!(cades["qualified_signature_claimed"], false);
}

fn assert_has_blocker(body: &Value, id: &str) {
    let blockers = body["profile"]["blockers"]
        .as_array()
        .expect("blockers array");
    assert!(
        blockers.iter().any(|blocker| blocker["id"] == id),
        "expected blocker {id}, got {blockers:?}"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn asic_signature_validation_bounded_s_cades_returns_valid_local_result() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let provider = provider(1);
    let (container, _cades) =
        sign_asic_s(&provider, "document.txt", b"hello ASiC", signing_time()).expect("asic s");

    let (status, body) = send(&state, post_asic(&token, &container)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "valid");
    assert_eq!(
        body["profile"]["profile_shape"],
        "asic_s_cades_single_payload"
    );
    assert_eq!(
        body["profile"]["bounded_profile"],
        "asic_s_cades_single_payload"
    );
    assert_eq!(body["profile"]["bounded_supported_candidate"], true);
    assert_eq!(
        body["profile"]["member_paths"]["payloads"],
        json!(["document.txt"])
    );
    assert_eq!(body["cades"]["status"], "valid");
    assert_eq!(body["cades"]["validation_performed"], true);
    assert_eq!(body["cades"]["cryptographically_valid"], true);
    assert_eq!(body["cades"]["signed_content"]["kind"], "asic_s_payload");
    assert_eq!(
        body["cades"]["signed_content"]["member_path"],
        "document.txt"
    );
    assert_eq!(
        body["cades"]["signer_cert_sha256"]
            .as_str()
            .expect("cert hash")
            .len(),
        64
    );
    assert_cades_no_claim_boundaries(&body["cades"]);
}

#[tokio::test]
async fn asic_signature_validation_bounded_e_cades_two_payloads_validates_manifest() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let provider = provider(2);
    let payloads = [
        AsicPayload {
            name: "a.txt",
            bytes: b"alpha",
            mime_type: Some("text/plain"),
        },
        AsicPayload {
            name: "b.txt",
            bytes: b"bravo",
            mime_type: Some("text/plain"),
        },
    ];
    let (container, _cades) = sign_asic_e(&provider, &payloads, signing_time()).expect("asic e");

    let (status, body) = send(&state, post_asic(&token, &container)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "valid");
    assert_eq!(
        body["profile"]["profile_shape"],
        "asic_e_cades_single_manifest"
    );
    assert_eq!(
        body["profile"]["bounded_profile"],
        "asic_e_cades_single_manifest"
    );
    assert_eq!(body["cades"]["status"], "valid");
    assert_eq!(body["cades"]["signed_content"]["kind"], "asic_e_manifest");
    assert_eq!(
        body["cades"]["signed_content"]["member_path"],
        ASICE_MANIFEST_PATH
    );
    let refs = body["profile"]["manifest_diagnostics"][0]["data_object_references"]
        .as_array()
        .expect("data object refs");
    assert_eq!(refs.len(), 2);
    assert!(
        refs.iter()
            .all(|reference| reference["digest_matches"] == true)
    );
    assert_cades_no_claim_boundaries(&body["cades"]);
}

#[tokio::test]
async fn asic_signature_validation_xades_s_and_e_are_structured_unsupported() {
    let state = seeded_state();
    let token = owner_session(&state).await;

    for (container, shape) in [
        (asic_s_xades_container(), "asic_s_xades"),
        (asic_e_xades_container(), "asic_e_xades"),
    ] {
        let (status, body) = send(&state, post_asic(&token, &container)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_no_claim_boundaries(&body);
        assert_eq!(body["status"], "unsupported");
        assert_eq!(body["profile"]["profile_shape"], shape);
        assert_eq!(body["profile"]["signature_profile"], "xades");
        assert_has_blocker(&body, "xades_not_supported");
        assert!(body["cades"].is_null(), "{body}");
        assert_eq!(body["xades_validation_performed"], false);
    }
}

#[tokio::test]
async fn asic_signature_validation_profile_blockers_remain_structured() {
    let state = seeded_state();
    let token = owner_session(&state).await;

    for (label, container, blocker) in [
        (
            "multiple manifests",
            asic_e_multiple_manifests_container(),
            "asic_e_multiple_manifests",
        ),
        (
            "multiple signatures",
            asic_e_multiple_signatures_container(),
            "asic_e_multiple_cades_signatures",
        ),
        (
            "missing manifest",
            asic_e_missing_manifest_container(),
            "asic_e_missing_manifest",
        ),
        (
            "digest mismatch",
            asic_e_digest_mismatch_container(),
            "asic_e_manifest_digest_mismatch",
        ),
        (
            "ASiCManifestExtensions",
            asic_e_manifest_extensions_container(),
            "asic_e_manifest_parse_failed",
        ),
    ] {
        let (status, body) = send(&state, post_asic(&token, &container)).await;

        assert_eq!(status, StatusCode::OK, "{label}: {body}");
        assert_no_claim_boundaries(&body);
        assert_has_blocker(&body, blocker);
        assert_eq!(
            body["profile"]["bounded_supported_candidate"], false,
            "{label}: {body}"
        );
        assert!(body["cades"].is_null(), "{label}: {body}");
    }
}

#[tokio::test]
async fn asic_signature_validation_blocks_oversized_uncompressed_zip_member() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let container = compressed_oversized_member_container();
    assert!(
        container.len() < 16 * 1024 * 1024,
        "compressed fixture must stay under the endpoint byte cap"
    );

    let (status, body) = send(&state, post_asic(&token, &container)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "invalid");
    assert_has_blocker(&body, "member_uncompressed_size_exceeded");
    assert_eq!(body["profile"]["bounded_supported_candidate"], false);
    assert!(body["cades"].is_null(), "{body}");
}

#[tokio::test]
async fn asic_signature_validation_bad_inputs_fail_with_validation_errors() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let provider = provider(3);
    let (valid_container, _cades) =
        sign_asic_s(&provider, "document.txt", b"hello", signing_time()).expect("asic s");

    let (status, body) = send(
        &state,
        post_asic_body(&token, json!({ "asic_base64": "not valid base64!" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["error"].as_str().expect("error").contains("base64"));

    let (status, body) = send(
        &state,
        post_asic_body(
            &token,
            json!({
                "asic_base64": B64.encode(&valid_container),
                "declared_sha256": "0".repeat(64)
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["error"].as_str().expect("error").contains("SHA-256"));

    let (status, body) = send(
        &state,
        post_asic_body(
            &token,
            json!({
                "asic_base64": B64.encode(&valid_container),
                "declared_size_bytes": valid_container.len() + 1
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["error"].as_str().expect("error").contains("size"));

    let (status, body) = send(&state, post_asic(&token, &unsafe_member_container())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body["error"].as_str().expect("error").contains("unsafe"));

    let (status, body) = send(&state, post_asic(&token, b"not a zip")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(
        body["error"]
            .as_str()
            .expect("error")
            .contains("readable ZIP")
    );
}

#[tokio::test]
async fn asic_signature_validation_response_claim_boundaries_stay_false() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let provider = provider(4);
    let (container, _cades) =
        sign_asic_s(&provider, "document.txt", b"claims", signing_time()).expect("asic s");

    let (status, valid_body) = send(&state, post_asic(&token, &container)).await;
    assert_eq!(status, StatusCode::OK, "{valid_body}");
    assert_no_claim_boundaries(&valid_body);
    assert_cades_no_claim_boundaries(&valid_body["cades"]);

    let (status, xades_body) = send(&state, post_asic(&token, &asic_s_xades_container())).await;
    assert_eq!(status, StatusCode::OK, "{xades_body}");
    assert_no_claim_boundaries(&xades_body);
    assert!(xades_body["cades"].is_null());
}
