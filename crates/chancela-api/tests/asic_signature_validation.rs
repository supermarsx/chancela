use std::io::{Cursor, Read, Write};
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
    ASICS_MIMETYPE, AsicEMultiSignRequest, AsicPayload, EvidentiaryLevel, MockProvider,
    SignatureAlgorithm, SignerProvider, SigningError, SigningFamily, Timestamp, TimestampProvider,
    XadesLevel, build_asic_e_manifest, sha256_content_digest, sign_asic_e, sign_asic_e_multi,
    sign_asic_s, sign_asic_s_xades, sign_detached_cades,
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

struct PatchingTsa;

fn patched_timestamp(digest: &[u8; 32]) -> Timestamp {
    let tsa = chancela_tsa::TsaClient::new(chancela_tsa::MockTsaTransport::from_fixture());
    let request = chancela_tsa::TimestampRequest::new(chancela_tsa::mock::FIXTURE_DIGEST)
        .with_nonce(chancela_tsa::mock::FIXTURE_NONCE)
        .without_certificate();
    let mut ts = tsa.stamp(&request).expect("fixture timestamp");
    let pos = ts
        .token_der
        .windows(chancela_tsa::mock::FIXTURE_DIGEST.len())
        .position(|w| w == chancela_tsa::mock::FIXTURE_DIGEST)
        .expect("fixture imprint present in token");
    ts.token_der[pos..pos + digest.len()].copy_from_slice(digest);
    ts
}

impl TimestampProvider for PatchingTsa {
    fn timestamp_digest(&self, digest: &[u8; 32]) -> Result<Timestamp, SigningError> {
        Ok(patched_timestamp(digest))
    }

    fn timestamp_data(&self, data: &[u8]) -> Result<Timestamp, SigningError> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        Ok(patched_timestamp(&digest))
    }
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

fn replace_member(container: &[u8], target: &str, new_bytes: &[u8]) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(container)).expect("read zip");
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default());
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).expect("member");
        let name = file.name().to_owned();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("read member");
        if name == target {
            bytes = new_bytes.to_vec();
        }
        out.start_file(&name, options).expect("start member");
        out.write_all(&bytes).expect("write member");
    }
    out.finish().expect("zip finish").into_inner()
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

fn asic_s_xades_container(serial: u8) -> Vec<u8> {
    let provider = provider(serial);
    sign_asic_s_xades(
        &provider,
        "payload.txt",
        b"payload",
        signing_time(),
        XadesLevel::B,
        None,
    )
    .expect("asic s xades")
}

fn asic_e_xades_container(serial: u8) -> Vec<u8> {
    let provider = provider(serial);
    let payloads = [AsicPayload {
        name: "payload.txt",
        bytes: b"payload",
        mime_type: Some("text/plain"),
    }];
    let xades_signers: [&dyn SignerProvider; 1] = [&provider];
    sign_asic_e_multi(AsicEMultiSignRequest {
        payloads: &payloads,
        cades_signers: &[],
        xades_signers: &xades_signers,
        signing_time: signing_time(),
        xades_level: XadesLevel::B,
        xades_tsa: None,
        archive_tsa: None,
    })
    .expect("asic e xades")
}

fn mixed_asic_e_with_archive_container() -> Vec<u8> {
    let cades = provider(31);
    let xades = provider(32);
    let payloads = [
        AsicPayload {
            name: "minutes.txt",
            bytes: b"approved minutes",
            mime_type: Some("text/plain"),
        },
        AsicPayload {
            name: "attachments/votes.csv",
            bytes: b"member,vote\nA,yes\nB,yes\n",
            mime_type: Some("text/csv"),
        },
    ];
    let cades_signers: [&dyn SignerProvider; 1] = [&cades];
    let xades_signers: [&dyn SignerProvider; 1] = [&xades];
    sign_asic_e_multi(AsicEMultiSignRequest {
        payloads: &payloads,
        cades_signers: &cades_signers,
        xades_signers: &xades_signers,
        signing_time: signing_time(),
        xades_level: XadesLevel::B,
        xades_tsa: None,
        archive_tsa: Some(&PatchingTsa),
    })
    .expect("mixed asic e")
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
    assert_eq!(body["scope"], "local_technical_asic_signature_evidence");
    assert_eq!(body["legal_validity_claimed"], false);
    assert_eq!(body["qualified_signature_claimed"], false);
    assert_eq!(body["qualified_electronic_signature_claimed"], false);
    assert_eq!(body["qes_claimed"], false);
    assert_eq!(body["trust_validation"], "not_performed");
    assert_eq!(body["trust_anchor_validation"], "not_performed");
    assert_eq!(body["revocation_validation"], "not_performed");
    assert_eq!(body["live_provider_calls"], false);
    assert_eq!(body["live_tsl_fetching"], false);
    assert_eq!(body["live_tsa_fetching"], false);
    assert_eq!(body["live_ocsp_fetching"], false);
    assert_eq!(body["live_crl_fetching"], false);
    assert_eq!(body["provider_approval_claimed"], false);
    assert_eq!(body["b_lt_claimed"], false);
    assert_eq!(body["b_lta_claimed"], false);
    assert_eq!(body["ltv_claimed"], false);
    assert_eq!(body["production_asic_compliance_claimed"], false);
    assert_eq!(body["production_xades_conformance_claimed"], false);
    assert_eq!(body["eidas_legal_effect_claimed"], false);
    assert_eq!(body["signing_performed"], false);
    assert_eq!(body["storage_mutation_performed"], false);
    assert_eq!(body["archive_mutation_performed"], false);
}

fn assert_cades_no_claim_boundaries(cades: &Value) {
    assert_eq!(cades["evidence_scope"], "technical_evidence_only");
    assert_eq!(cades["trust_validation"], "not_performed");
    assert_eq!(cades["revocation_validation"], "not_performed");
    assert_eq!(cades["legal_validity_claimed"], false);
    assert_eq!(cades["qualified_signature_claimed"], false);
}

fn assert_technical_no_claim_boundaries(technical: &Value) {
    for signature in technical["signatures"]
        .as_array()
        .expect("technical signatures")
    {
        assert_eq!(signature["evidence_scope"], "technical_evidence_only");
        assert_eq!(signature["trust_validation"], "not_performed");
        assert_eq!(signature["revocation_validation"], "not_performed");
        assert_eq!(signature["provider_validation"], "not_performed");
        assert_eq!(signature["provider_approval_claimed"], false);
        assert_eq!(signature["legal_validity_claimed"], false);
        assert_eq!(signature["qualified_signature_claimed"], false);
        assert_eq!(signature["qes_claimed"], false);
        assert_eq!(
            signature["signature_timestamp_trust_validation"],
            "not_performed"
        );
    }
    for archive in technical["archive_timestamps"]
        .as_array()
        .expect("technical archive timestamps")
    {
        assert_eq!(archive["timestamp_trust_validation"], "not_performed");
        assert_eq!(archive["b_lta_claimed"], false);
        assert_eq!(archive["legal_validity_claimed"], false);
    }
}

fn assert_technical_performed(body: &Value, cryptographically_valid: bool) {
    let technical = &body["technical_validation"];
    assert_eq!(technical["validation_performed"], true);
    assert_eq!(
        technical["cryptographically_valid"],
        cryptographically_valid
    );
    assert_technical_no_claim_boundaries(technical);
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

fn assert_no_blocker(body: &Value, id: &str) {
    let blockers = body["profile"]["blockers"]
        .as_array()
        .expect("blockers array");
    assert!(
        blockers.iter().all(|blocker| blocker["id"] != id),
        "unexpected blocker {id}, got {blockers:?}"
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
    assert_eq!(body["xades_validation_performed"], false);
    assert_technical_performed(&body, true);
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
    let technical_signature = &body["technical_validation"]["signatures"][0];
    assert_eq!(technical_signature["kind"], "cades");
    assert_eq!(technical_signature["valid"], true);
    assert_eq!(
        technical_signature["covered_data_objects"],
        json!(["document.txt"])
    );
    assert_eq!(
        technical_signature["signer_cert_sha256"]
            .as_str()
            .expect("technical cert hash")
            .len(),
        64
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
    assert_eq!(body["xades_validation_performed"], false);
    assert_technical_performed(&body, true);
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
    let technical_signature = &body["technical_validation"]["signatures"][0];
    assert_eq!(technical_signature["kind"], "cades");
    assert_eq!(technical_signature["valid"], true);
    assert_eq!(technical_signature["manifest_path"], ASICE_MANIFEST_PATH);
    assert_eq!(
        technical_signature["covered_data_objects"],
        json!(["a.txt", "b.txt"])
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
async fn asic_signature_validation_xades_s_and_e_use_technical_report() {
    let state = seeded_state();
    let token = owner_session(&state).await;

    for (container, shape) in [
        (asic_s_xades_container(11), "asic_s_xades"),
        (asic_e_xades_container(12), "asic_e_xades"),
    ] {
        let (status, body) = send(&state, post_asic(&token, &container)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_no_claim_boundaries(&body);
        assert_eq!(body["status"], "valid");
        assert_eq!(body["profile"]["profile_shape"], shape);
        assert_eq!(body["profile"]["signature_profile"], "xades");
        assert_no_blocker(&body, "xades_not_supported");
        assert!(body["cades"].is_null(), "{body}");
        assert_eq!(body["xades_validation_performed"], true);
        assert_technical_performed(&body, true);
        assert_eq!(body["technical_validation"]["all_signatures_valid"], true);
        assert_eq!(
            body["technical_validation"]["signatures"][0]["kind"],
            "xades"
        );
        assert_eq!(body["technical_validation"]["signatures"][0]["valid"], true);
        assert_eq!(
            body["technical_validation"]["signatures"][0]["xades_level"],
            "b"
        );
        assert_eq!(
            body["technical_validation"]["signatures"][0]["signer_cert_sha256"]
                .as_str()
                .expect("cert hash")
                .len(),
            64
        );
    }

    let tampered = replace_member(&asic_s_xades_container(13), "payload.txt", b"tampered");
    let (status, body) = send(&state, post_asic(&token, &tampered)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "invalid");
    assert_eq!(body["xades_validation_performed"], true);
    assert!(body["cades"].is_null(), "{body}");
    assert_technical_performed(&body, false);
    assert_eq!(
        body["technical_validation"]["signatures"][0]["kind"],
        "xades"
    );
    assert_eq!(
        body["technical_validation"]["signatures"][0]["valid"],
        false
    );
    assert!(
        body["technical_validation"]["signatures"][0]["failure_reasons"]
            .as_array()
            .expect("failure reasons")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("payload.txt")),
        "{body}"
    );
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
        assert_technical_performed(&body, body["status"].as_str() == Some("valid"));
        assert_has_blocker(&body, blocker);
        assert_eq!(
            body["profile"]["bounded_supported_candidate"], false,
            "{label}: {body}"
        );
        assert!(body["cades"].is_null(), "{label}: {body}");
    }
}

#[tokio::test]
async fn asic_signature_validation_mixed_e_cades_xades_archive_timestamp_reports_consistency() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let container = mixed_asic_e_with_archive_container();

    let (status, body) = send(&state, post_asic(&token, &container)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "valid");
    assert_eq!(body["profile"]["signature_profile"], "mixed");
    assert_no_blocker(&body, "xades_not_supported");
    assert_eq!(body["xades_validation_performed"], true);
    assert!(body["cades"].is_null(), "{body}");
    assert_technical_performed(&body, true);
    let signatures = body["technical_validation"]["signatures"]
        .as_array()
        .expect("technical signatures");
    assert_eq!(signatures.len(), 2, "{body}");
    let cades = signatures
        .iter()
        .find(|signature| signature["kind"] == "cades")
        .expect("cades signature");
    assert_eq!(cades["valid"], true);
    assert_eq!(cades["manifest_path"], "META-INF/ASiCManifest001.xml");
    assert_eq!(
        cades["covered_data_objects"]
            .as_array()
            .expect("covered objects")
            .len(),
        2
    );
    let xades = signatures
        .iter()
        .find(|signature| signature["kind"] == "xades")
        .expect("xades signature");
    assert_eq!(xades["valid"], true);
    assert_eq!(xades["xades_level"], "b");
    let archive = &body["technical_validation"]["archive_timestamps"][0];
    assert_eq!(archive["manifest_path"], "META-INF/ASiCArchiveManifest.xml");
    assert_eq!(
        archive["timestamp_path"],
        "META-INF/ASiCArchiveManifest.tst"
    );
    assert_eq!(archive["valid"], true);
    assert_eq!(archive["imprint_matches_manifest"], true);
    assert_eq!(archive["references_valid"], true);
    assert_eq!(archive["timestamp_trust_validation"], "not_performed");
    assert_eq!(archive["b_lta_claimed"], false);
    assert_eq!(archive["legal_validity_claimed"], false);
}

#[tokio::test]
async fn asic_signature_validation_mixed_e_archive_timestamp_tamper_is_technical_only_invalid() {
    let state = seeded_state();
    let token = owner_session(&state).await;
    let container = mixed_asic_e_with_archive_container();
    let tampered = replace_member(&container, "minutes.txt", b"tampered minutes");

    let (status, body) = send(&state, post_asic(&token, &tampered)).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_claim_boundaries(&body);
    assert_eq!(body["status"], "invalid");
    assert_eq!(body["xades_validation_performed"], true);
    assert!(body["cades"].is_null(), "{body}");
    assert_technical_performed(&body, false);
    let signatures = body["technical_validation"]["signatures"]
        .as_array()
        .expect("technical signatures");
    assert_eq!(signatures.len(), 2, "{body}");
    assert!(
        signatures
            .iter()
            .all(|signature| signature["valid"] == false),
        "{body}"
    );
    assert!(
        signatures.iter().any(|signature| {
            signature["failure_reasons"]
                .as_array()
                .expect("failure reasons")
                .iter()
                .any(|reason| reason.as_str().unwrap_or_default().contains("minutes.txt"))
        }),
        "{body}"
    );
    let archive = &body["technical_validation"]["archive_timestamps"][0];
    assert_eq!(archive["valid"], false);
    assert_eq!(archive["references_valid"], false);
    assert_eq!(archive["timestamp_trust_validation"], "not_performed");
    assert_eq!(archive["b_lta_claimed"], false);
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
    assert_eq!(
        body["technical_validation"]["validation_performed"], false,
        "{body}"
    );
    assert_technical_no_claim_boundaries(&body["technical_validation"]);
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
    assert_eq!(valid_body["xades_validation_performed"], false);
    assert_technical_performed(&valid_body, true);
    assert_cades_no_claim_boundaries(&valid_body["cades"]);

    let (status, xades_body) = send(&state, post_asic(&token, &asic_s_xades_container(41))).await;
    assert_eq!(status, StatusCode::OK, "{xades_body}");
    assert_no_claim_boundaries(&xades_body);
    assert_eq!(xades_body["xades_validation_performed"], true);
    assert_technical_performed(&xades_body, true);
    assert!(xades_body["cades"].is_null());
}
