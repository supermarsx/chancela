//! Official Autenticacao.gov handoff import: the operator signs the sealed PDF outside Chancela and
//! imports the resulting signed PDF back as technical evidence only.

use std::str::FromStr;
use std::time::Duration as StdDuration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use der::Encode;
use der::asn1::{Any, BitString, ObjectIdentifier};
use serde_json::{Map, Value, json};
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
use chancela_cades::{
    RawSignature, SignatureAlgorithm, assemble_cades_b, signed_attributes_digest,
};
use chancela_core::ActId;
use chancela_pades::{SignOptions, sign_pdf, validate_pdf_signature};
use time::format_description::well_known::Rfc3339;

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

fn import_req(act_id: &str, token: &str, signed_pdf: &[u8]) -> Request<Body> {
    import_req_with_metadata(
        act_id,
        token,
        signed_pdf,
        "Autenticacao.gov",
        "operator_selected_cc_or_cmd",
    )
}

fn official_import_guardrail_ids() -> Vec<&'static str> {
    vec![
        "official_import_preserves_uploaded_signed_pdf_as_technical_evidence",
        "official_import_trust_validation_not_performed",
        "official_import_qualified_status_not_claimed",
        "official_import_legal_status_not_claimed",
        "official_import_no_secret_factor_collected",
    ]
}

fn external_invite_response_with_signed_pdf_req(token: &str, signed_pdf: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/signature/external-invites/respond")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "token": token,
                "decision": "accept",
                "signed_pdf_base64": B64.encode(signed_pdf),
                "filename": "external-signer-upload.pdf"
            })
            .to_string(),
        ))
        .expect("request builds")
}

fn import_req_with_metadata(
    act_id: &str,
    token: &str,
    signed_pdf: &[u8],
    provider: &str,
    source: &str,
) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/acts/{act_id}/signature/official/import"),
        token,
        json!({
            "signed_pdf_base64": B64.encode(signed_pdf),
            "provider": provider,
            "source": source,
            "filename": "signed-by-official-app.pdf",
            "acknowledged_guardrail_ids": official_import_guardrail_ids()
        }),
    )
}

fn import_req_without_acknowledgement(
    act_id: &str,
    token: &str,
    signed_pdf: &[u8],
) -> Request<Body> {
    json_req(
        "POST",
        &format!("/v1/acts/{act_id}/signature/official/import"),
        token,
        json!({
            "signed_pdf_base64": B64.encode(signed_pdf),
            "provider": "Autenticacao.gov",
            "source": "operator_selected_cc_or_cmd",
            "filename": "signed-by-official-app.pdf"
        }),
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

async fn create_external_invite(state: &AppState, token: &str, act_id: &str) -> String {
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::days(1))
        .format(&Rfc3339)
        .expect("expires_at");
    let (status, invite) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            token,
            json!({
                "recipient_name": "External Signer",
                "recipient_email": "external.signer@example.test",
                "provider_hint": "manual-provider",
                "expires_at": expires_at,
                "purpose": "Assinar a ata por fluxo externo"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create invite: {invite}");
    invite["token"].as_str().expect("invite token").to_owned()
}

async fn create_external_envelope(
    state: &AppState,
    token: &str,
    act_id: &str,
    linked_slot_identity_requirements: Vec<&str>,
) -> Value {
    let mut linked_slot = json!({
        "signer_label": "Linked External Signer",
        "contact_hint": "external.signer@example.test",
        "required": true
    });
    if !linked_slot_identity_requirements.is_empty() {
        linked_slot["identity_requirements"] = json!(linked_slot_identity_requirements);
    }

    let (status, envelope) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/external-signing/envelopes"),
            token,
            json!({
                "order_policy": "parallel",
                "slots": [
                    linked_slot,
                    { "signer_label": "Second External Signer", "required": true }
                ]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create envelope: {envelope}");
    envelope
}

async fn create_linked_external_invite(
    state: &AppState,
    token: &str,
    act_id: &str,
    envelope_id: &str,
    slot_id: &str,
) -> String {
    let expires_at = (time::OffsetDateTime::now_utc() + time::Duration::days(1))
        .format(&Rfc3339)
        .expect("expires_at");
    let (status, invite) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/signature/external-invites"),
            token,
            json!({
                "recipient_name": "External Signer",
                "recipient_email": "external.signer@example.test",
                "provider_hint": "manual-provider",
                "external_envelope_id": envelope_id,
                "external_slot_id": slot_id,
                "expires_at": expires_at,
                "purpose": "Assinar a ata por fluxo externo"
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create linked invite: {invite}"
    );
    assert_eq!(invite["invite"]["workflow"], "external_envelope");
    assert_eq!(
        invite["invite"]["external_envelope"]["slot_status"],
        "initiated"
    );
    invite["token"].as_str().expect("invite token").to_owned()
}

async fn create_signing_act(state: &AppState, token: &str, book_id: &str, title: &str) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({ "book_id": book_id, "title": title, "channel": "Physical" }),
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
                "agenda": [{ "number": 1, "text": format!("Aprovacao das contas - {title}") }],
                "attendance_reference": "Lista de presencas",
                "deliberations": format!("Deliberacao aprovada para {title}.")
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

async fn sealed_pdf_bytes(state: &AppState, act_id: &str) -> Vec<u8> {
    let act_id = ActId(Uuid::parse_str(act_id).expect("act uuid"));
    state
        .documents
        .read()
        .await
        .get(&act_id)
        .expect("sealed document")
        .pdf_bytes
        .clone()
}

fn signed_pdf_for_import(pdf: &[u8], serial: u8) -> Vec<u8> {
    let signer = RsaSigner::new("Official handoff import test", serial);
    let cert_der = signer.cert_der();
    let signing_time =
        time::OffsetDateTime::from_unix_timestamp(1_783_596_800).expect("fixed signing time");
    let opts = SignOptions {
        field_name: Some("AssinaturaImportada".to_owned()),
        signing_time: Some("D:20260709120000Z".to_owned()),
        reason: Some("Official handoff import test".to_owned()),
        location: None,
        contact_info: None,
    };
    sign_pdf(pdf, &opts, |byterange_digest| {
        let attrs_digest = signed_attributes_digest(byterange_digest, &cert_der, signing_time)?;
        let signature = sign_rsa_digest_info(&signer.key, &attrs_digest);
        let raw = RawSignature::new(
            SignatureAlgorithm::RsaPkcs1Sha256,
            signature,
            cert_der.clone(),
            Vec::new(),
        );
        assemble_cades_b(&raw, byterange_digest, signing_time)
    })
    .expect("PAdES signing")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn signed_event_count(state: &AppState, token: &str, act_id: &str) -> usize {
    event_kind_count(state, token, act_id, "document.signed").await
}

async fn event_kind_count(state: &AppState, token: &str, act_id: &str, kind: &str) -> usize {
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
        .filter(|e| e["kind"] == kind)
        .count()
}

async fn document_signed_event_payload_digest(state: &AppState, act_id: &str) -> String {
    let ledger = state.ledger.read().await;
    ledger
        .events()
        .iter()
        .rev()
        .find(|event| {
            event.kind == "document.signed" && event.scope.contains(&format!("act:{act_id}"))
        })
        .map(|event| {
            event
                .payload_digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
        .expect("document.signed event")
}

fn legal_validation_json() -> Value {
    json!({
        "pades_valid": true,
        "byte_range_covers_whole_file": true,
        "sealed_pdf_prefix_match": true,
        "trust_validation": "not_performed",
        "trust_validation_performed": false,
        "qualified_status_claimed": false,
        "legal_status_claimed": false
    })
}

fn expected_official_import_event_digest(
    act_id: &str,
    document_id: &str,
    signed_pdf_digest: &str,
) -> String {
    let payload = json!({
        "act_id": act_id,
        "document_id": document_id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": "AutenticacaoGovOfficialHandoff",
        "evidentiary_level": "ImportedOfficialHandoffTechnicalEvidence",
        "trusted_list_status": null,
        "profile": "application/pdf; profile=PAdES-B-B",
        "legal_validation": legal_validation_json(),
        "validation": {
            "pades_cryptographic_validation": "valid",
            "byte_range_covers_whole_file_except_contents": true,
            "sealed_pdf_prefix_match": true,
            "trust_validation": "not_performed",
            "qualified_status_claimed": false
        },
        "client_declared_metadata": {
            "present": true,
            "authoritative": false
        },
        "guardrail_ids": official_import_guardrail_ids(),
        "acknowledged_guardrail_ids": official_import_guardrail_ids(),
        "guardrail_acknowledgement": {
            "required_guardrail_ids": official_import_guardrail_ids(),
            "acknowledged_guardrail_ids": official_import_guardrail_ids(),
            "all_required_guardrails_acknowledged": true
        },
        "acknowledgement_notice": "Official handoff import stores technical signed-PDF evidence only; acknowledgements record guardrails and do not claim trust-list, qualified-signature, or legal completion.",
        "status_scope": "technical_evidence_only",
        "secrets_in_payload": {
            "pin": false,
            "otp": false,
            "can": false,
            "credential": false,
            "private_key": false,
            "passphrase": false,
            "token": false
        }
    });
    let bytes = serde_json::to_vec(&payload).expect("event payload serializes");
    sha256_hex(&bytes)
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

#[tokio::test]
async fn official_import_stores_exact_signed_pdf_as_non_qualified_evidence() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata oficial importada").await;
    seal_act(&state, &token, &act_id).await;

    let sealed_pdf = sealed_pdf_bytes(&state, &act_id).await;
    let signed_pdf = signed_pdf_for_import(&sealed_pdf, 1);
    validate_pdf_signature(&signed_pdf).expect("test signed PDF validates");

    let (status, imported) = send(&state, import_req(&act_id, &token, &signed_pdf)).await;
    assert_eq!(status, StatusCode::OK, "official import: {imported}");
    assert_eq!(imported["family"], "AutenticacaoGovOfficialHandoff");
    assert_eq!(
        imported["evidentiary_level"],
        "ImportedOfficialHandoffTechnicalEvidence"
    );
    assert_eq!(imported["trusted_list_status"], Value::Null);
    assert_eq!(imported["legal_validation"], legal_validation_json());
    assert_eq!(imported["qualification_claimed"], false);
    assert_eq!(imported["client_metadata_authoritative"], false);
    assert_eq!(
        imported["guardrail_ids"],
        json!(official_import_guardrail_ids())
    );
    assert_eq!(
        imported["acknowledged_guardrail_ids"],
        json!(official_import_guardrail_ids())
    );
    assert!(
        imported["acknowledgement_notice"]
            .as_str()
            .is_some_and(|notice| notice.contains("technical signed-PDF evidence"))
    );
    assert_eq!(imported["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(imported["signed_pdf_digest"], sha256_hex(&signed_pdf));
    assert_eq!(
        document_signed_event_payload_digest(&state, &act_id).await,
        expected_official_import_event_digest(
            &act_id,
            imported["document_id"].as_str().expect("document_id"),
            imported["signed_pdf_digest"]
                .as_str()
                .expect("signed_pdf_digest")
        )
    );

    let (status, downloaded) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        downloaded, signed_pdf,
        "uploaded signed bytes are preserved"
    );

    let (status, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(view["signed"]["family"], "AutenticacaoGovOfficialHandoff");
    assert_eq!(
        view["signed"]["evidentiary_level"],
        "ImportedOfficialHandoffTechnicalEvidence"
    );
    assert_ne!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(view["evidence"]["current_level"], "B-B");
    assert_eq!(view["evidence"]["legal_b_lt_claimed"], false);
    assert_eq!(view["evidence"]["status_scope"], "technical_evidence_only");
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
}

#[tokio::test]
async fn official_import_requires_guardrail_acknowledgement_without_artifact_or_event() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata acknowledge").await;
    seal_act(&state, &token, &act_id).await;

    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &act_id).await, 8);
    let (status, body) = send(
        &state,
        import_req_without_acknowledgement(&act_id, &token, &signed_pdf),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "missing acknowledgement refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("acknowledged_guardrail_ids")),
        "error names acknowledgement field: {body}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
}

#[tokio::test]
async fn external_invite_response_upload_stores_signed_pdf_as_technical_evidence() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata convite externo").await;
    seal_act(&state, &token, &act_id).await;
    let invite_token = create_external_invite(&state, &token, &act_id).await;

    let sealed_pdf = sealed_pdf_bytes(&state, &act_id).await;
    let signed_pdf = signed_pdf_for_import(&sealed_pdf, 7);
    validate_pdf_signature(&signed_pdf).expect("test signed PDF validates");

    let (status, response) = send(
        &state,
        external_invite_response_with_signed_pdf_req(&invite_token, &signed_pdf),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "external invite response: {response}"
    );
    assert_eq!(response["status"], "accepted");
    assert_eq!(
        response["signed_artifact"]["family"],
        "ExternalSignerHandoff"
    );
    assert_eq!(
        response["signed_artifact"]["evidentiary_level"],
        "ExternalSignedPdfTechnicalEvidence"
    );
    assert_eq!(
        response["signed_artifact"]["signed_pdf_digest"],
        sha256_hex(&signed_pdf)
    );
    assert_eq!(
        response["signed_artifact"]["status_scope"],
        "technical_evidence_only"
    );
    assert_eq!(response["signed_artifact"]["qualification_claimed"], false);
    assert_eq!(response["signed_artifact"]["legal_status_claimed"], false);

    let (status, downloaded) = send_bytes(
        &state,
        get_req(&format!("/v1/acts/{act_id}/document/signed"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        downloaded, signed_pdf,
        "uploaded signed bytes are preserved"
    );

    let (status, view) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "signed");
    assert_eq!(view["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(view["signed"]["family"], "ExternalSignerHandoff");
    assert_eq!(
        view["signed"]["evidentiary_level"],
        "ExternalSignedPdfTechnicalEvidence"
    );
    assert_ne!(view["signed"]["evidentiary_level"], "Qualified");
    assert_eq!(view["signed"]["trusted_list_status"], Value::Null);
    assert_eq!(view["evidence"]["current_level"], "B-B");
    assert_eq!(view["evidence"]["legal_b_lt_claimed"], false);
    assert_eq!(view["evidence"]["legal_b_lta_claimed"], false);
    assert_eq!(view["evidence"]["status_scope"], "technical_evidence_only");
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
}

#[tokio::test]
async fn linked_external_invite_upload_marks_only_linked_slot_signed() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata convite ligado").await;
    seal_act(&state, &token, &act_id).await;
    let envelope = create_external_envelope(&state, &token, &act_id, Vec::new()).await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let linked_slot_id = envelope["slots"][0]["id"].as_str().expect("linked slot id");
    let other_slot_id = envelope["slots"][1]["id"].as_str().expect("other slot id");
    let invite_token =
        create_linked_external_invite(&state, &token, &act_id, envelope_id, linked_slot_id).await;
    let envelope_update_events_before_upload = event_kind_count(
        &state,
        &token,
        &act_id,
        "signature.external_envelope.updated",
    )
    .await;

    let sealed_pdf = sealed_pdf_bytes(&state, &act_id).await;
    let signed_pdf = signed_pdf_for_import(&sealed_pdf, 9);
    validate_pdf_signature(&signed_pdf).expect("test signed PDF validates");
    let signed_pdf_digest = sha256_hex(&signed_pdf);

    let (status, response) = send(
        &state,
        external_invite_response_with_signed_pdf_req(&invite_token, &signed_pdf),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "linked invite response: {response}");
    assert_eq!(response["status"], "accepted");
    assert_eq!(response["workflow"], "external_envelope");
    assert_eq!(response["external_envelope"]["slot_id"], linked_slot_id);
    assert_eq!(response["external_envelope"]["slot_status"], "signed");
    assert!(
        response["external_envelope"]
            .get("technical_upload_auto_sign")
            .is_none()
    );
    assert_eq!(
        response["signed_artifact"]["family"],
        "ExternalSignerHandoff"
    );
    assert_eq!(
        response["signed_artifact"]["signed_pdf_digest"],
        signed_pdf_digest
    );
    assert_eq!(
        response["signed_artifact"]["status_scope"],
        "technical_evidence_only"
    );
    assert_eq!(response["signed_artifact"]["qualification_claimed"], false);
    assert_eq!(response["signed_artifact"]["legal_status_claimed"], false);

    let (status, envelope) = send(
        &state,
        get_req(
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read linked envelope: {envelope}");
    assert_eq!(envelope["completed"], false);
    assert_eq!(envelope["completion"]["required_slot_count"], 2);
    assert_eq!(envelope["completion"]["signed_required_slot_count"], 1);
    assert_eq!(
        envelope["completion"]["blocking_required_slot_ids"],
        json!([other_slot_id])
    );
    assert_eq!(envelope["slots"][0]["id"], linked_slot_id);
    assert_eq!(envelope["slots"][0]["status"], "signed");
    assert_eq!(envelope["slots"][1]["id"], other_slot_id);
    assert_eq!(envelope["slots"][1]["status"], "pending");
    assert_eq!(
        envelope["slots"][0]["evidence"][0]["label"],
        "external signed PDF artifact"
    );
    assert!(
        envelope["slots"][0]["evidence"][0]["reference"]
            .as_str()
            .expect("artifact reference")
            .starts_with("act-signed-document:")
    );
    assert_eq!(
        envelope["slots"][0]["evidence"][0]["digest"],
        signed_pdf_digest
    );
    assert_eq!(
        envelope["slots"][0]["evidence"][1]["label"],
        "external invite upload source"
    );
    assert!(
        envelope["slots"][0]["evidence"][1]["reference"]
            .as_str()
            .expect("source reference")
            .contains(":signed-pdf")
    );
    assert_eq!(
        envelope["slots"][0]["evidence"][1]["digest"],
        signed_pdf_digest
    );
    assert_eq!(
        envelope["slots"][1]["evidence"]
            .as_array()
            .expect("other slot evidence")
            .len(),
        0
    );

    let (status, signature) = send(
        &state,
        get_req(&format!("/v1/acts/{act_id}/signature"), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signature view: {signature}");
    assert_eq!(signature["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(signature["signed"]["family"], "ExternalSignerHandoff");
    assert_eq!(signature["signed"]["trusted_list_status"], Value::Null);
    assert_eq!(signature["evidence"]["legal_b_lt_claimed"], false);
    assert_eq!(signature["evidence"]["legal_b_lta_claimed"], false);
    assert_eq!(
        signature["evidence"]["status_scope"],
        "technical_evidence_only"
    );
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
    assert_eq!(state.signed_documents.read().await.len(), 1);
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "signature.external_envelope.updated",
        )
        .await,
        envelope_update_events_before_upload + 1
    );

    let (status, replay) = send(
        &state,
        external_invite_response_with_signed_pdf_req(&invite_token, &signed_pdf),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "replay response is OK: {replay}");
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
    assert_eq!(state.signed_documents.read().await.len(), 1);
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "signature.external_envelope.updated",
        )
        .await,
        envelope_update_events_before_upload + 1
    );
    let (status, envelope_after_replay) = send(
        &state,
        get_req(
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "read envelope after replay: {envelope_after_replay}"
    );
    assert_eq!(
        envelope_after_replay["slots"][0]["evidence"]
            .as_array()
            .expect("linked slot evidence")
            .len(),
        2
    );
}

#[tokio::test]
async fn linked_external_invite_upload_does_not_auto_sign_identity_required_slot() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(
        &state,
        &token,
        &book_id,
        "Ata convite ligado com identidade",
    )
    .await;
    seal_act(&state, &token, &act_id).await;
    let envelope = create_external_envelope(&state, &token, &act_id, vec!["contact_control"]).await;
    let envelope_id = envelope["id"].as_str().expect("envelope id");
    let linked_slot_id = envelope["slots"][0]["id"].as_str().expect("linked slot id");
    let invite_token =
        create_linked_external_invite(&state, &token, &act_id, envelope_id, linked_slot_id).await;
    let envelope_update_events_before_upload = event_kind_count(
        &state,
        &token,
        &act_id,
        "signature.external_envelope.updated",
    )
    .await;

    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &act_id).await, 10);
    validate_pdf_signature(&signed_pdf).expect("test signed PDF validates");

    let (status, response) = send(
        &state,
        external_invite_response_with_signed_pdf_req(&invite_token, &signed_pdf),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "identity-gated linked invite response: {response}"
    );
    assert_eq!(response["status"], "accepted");
    assert_eq!(response["external_envelope"]["slot_status"], "initiated");
    assert_eq!(
        response["external_envelope"]["technical_upload_auto_sign"]["status"],
        "blocked"
    );
    assert!(
        response["external_envelope"]["technical_upload_auto_sign"]["reason"]
            .as_str()
            .expect("blocked reason")
            .contains("identity requirements")
    );
    assert_eq!(
        response["signed_artifact"]["family"],
        "ExternalSignerHandoff"
    );
    assert_eq!(response["signed_artifact"]["qualification_claimed"], false);
    assert_eq!(response["signed_artifact"]["legal_status_claimed"], false);

    let (status, envelope) = send(
        &state,
        get_req(
            &format!("/v1/external-signing/envelopes/{envelope_id}"),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "read identity-gated envelope: {envelope}"
    );
    assert_eq!(envelope["slots"][0]["status"], "initiated");
    assert_eq!(
        envelope["slots"][0]["identity_requirements"],
        json!(["contact_control"])
    );
    assert_eq!(
        envelope["slots"][0]["evidence"]
            .as_array()
            .expect("identity slot evidence")
            .len(),
        0
    );
    assert_eq!(envelope["completion"]["signed_required_slot_count"], 0);
    assert_eq!(
        envelope["completion"]["blocking_required_slot_ids"],
        json!([
            linked_slot_id,
            envelope["slots"][1]["id"].as_str().expect("other slot id")
        ])
    );
    assert_eq!(signed_event_count(&state, &token, &act_id).await, 1);
    assert_eq!(
        event_kind_count(
            &state,
            &token,
            &act_id,
            "signature.external_envelope.updated",
        )
        .await,
        envelope_update_events_before_upload
    );
}

#[tokio::test]
async fn official_import_client_declared_provider_source_cannot_claim_trust_or_qualification() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    state
        .settings
        .write()
        .await
        .signing
        .require_qualified_for_seal = true;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata metadados hostis").await;
    seal_act(&state, &token, &act_id).await;

    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &act_id).await, 6);
    let (status, imported) = send(
        &state,
        import_req_with_metadata(
            &act_id,
            &token,
            &signed_pdf,
            "Qualified Trust Provider - Granted",
            "qualified:legal:trusted_list_status=Granted",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "official import: {imported}");
    assert_eq!(imported["family"], "AutenticacaoGovOfficialHandoff");
    assert_eq!(
        imported["evidentiary_level"],
        "ImportedOfficialHandoffTechnicalEvidence"
    );
    assert_eq!(imported["trusted_list_status"], Value::Null);
    assert_eq!(imported["qualification_claimed"], false);
    assert_eq!(imported["client_metadata_authoritative"], false);
    assert_eq!(imported["legal_validation"], legal_validation_json());
    assert_eq!(imported["finalization"], "aguarda_assinatura_qualificada");
    assert_eq!(
        document_signed_event_payload_digest(&state, &act_id).await,
        expected_official_import_event_digest(
            &act_id,
            imported["document_id"].as_str().expect("document_id"),
            imported["signed_pdf_digest"]
                .as_str()
                .expect("signed_pdf_digest")
        )
    );
}

#[tokio::test]
async fn official_import_rejects_unsigned_or_malformed_pdf_without_artifact_or_event() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata sem assinatura").await;
    seal_act(&state, &token, &act_id).await;
    let unsigned_pdf = sealed_pdf_bytes(&state, &act_id).await;

    for candidate in [unsigned_pdf, b"not a pdf".to_vec()] {
        let (status, body) = send(&state, import_req(&act_id, &token, &candidate)).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid import refused: {body}"
        );
        assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
    }
}

#[tokio::test]
async fn official_import_rejects_signed_pdf_bound_to_different_act() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let source_act = create_signing_act(&state, &token, &book_id, "Ata origem").await;
    seal_act(&state, &token, &source_act).await;
    let target_act = create_signing_act(&state, &token, &book_id, "Ata destino").await;
    seal_act(&state, &token, &target_act).await;

    let source_pdf = sealed_pdf_bytes(&state, &source_act).await;
    let signed_for_source = signed_pdf_for_import(&source_pdf, 2);
    let (status, body) = send(&state, import_req(&target_act, &token, &signed_for_source)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "wrong-act signed PDF refused: {body}"
    );
    assert_no_signed_artifact_or_event(&state, &token, &target_act).await;
    assert_no_signed_artifact_or_event(&state, &token, &source_act).await;
}

#[tokio::test]
async fn official_import_rejects_unsealed_act_and_duplicate_signature() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let sealed_act = create_signing_act(&state, &token, &book_id, "Ata selada").await;
    seal_act(&state, &token, &sealed_act).await;
    let unsealed_act = create_signing_act(&state, &token, &book_id, "Ata ainda nao selada").await;

    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &sealed_act).await, 3);
    let (status, body) = send(&state, import_req(&unsealed_act, &token, &signed_pdf)).await;
    assert_eq!(status, StatusCode::CONFLICT, "unsealed act refused: {body}");
    assert_no_signed_artifact_or_event(&state, &token, &unsealed_act).await;

    let (status, imported) = send(&state, import_req(&sealed_act, &token, &signed_pdf)).await;
    assert_eq!(status, StatusCode::OK, "first import succeeds: {imported}");
    let (status, body) = send(&state, import_req(&sealed_act, &token, &signed_pdf)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "duplicate import refused: {body}"
    );
    assert_eq!(signed_event_count(&state, &token, &sealed_act).await, 1);
}

#[tokio::test]
async fn official_import_json_schema_denies_unknown_secret_fields() {
    let state = AppState::default();
    let (token, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &token).await;
    let act_id = create_signing_act(&state, &token, &book_id, "Ata schema").await;
    seal_act(&state, &token, &act_id).await;
    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &act_id).await, 4);

    for field in [
        "pin",
        "otp",
        "can",
        "credential",
        "activation",
        "private_key",
        "passphrase",
        "token",
        "access_token",
        "refresh_token",
    ] {
        let mut body = Map::new();
        body.insert(
            "signed_pdf_base64".to_owned(),
            Value::String(B64.encode(&signed_pdf)),
        );
        body.insert(
            field.to_owned(),
            Value::String("secret-material".to_owned()),
        );
        let (status, err) = send(
            &state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/signature/official/import"),
                &token,
                Value::Object(body),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "secret field {field} must be denied: {err}"
        );
        assert_no_signed_artifact_or_event(&state, &token, &act_id).await;
    }
}

#[tokio::test]
async fn official_import_requires_signing_permission() {
    let state = AppState::default();
    let (owner, _) = bootstrap(&state).await;
    let book_id = seed_book(&state, &owner).await;
    let act_id = create_signing_act(&state, &owner, &book_id, "Ata RBAC").await;
    seal_act(&state, &owner, &act_id).await;
    let signed_pdf = signed_pdf_for_import(&sealed_pdf_bytes(&state, &act_id).await, 5);

    let (status, limited) = send(
        &state,
        json_req(
            "POST",
            "/v1/users",
            &owner,
            json!({ "username": "leitor.user", "display_name": "Leitor" }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create limited user: {limited}"
    );
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

    let limited_token = open_session(&state, &limited_id).await;
    let (status, body) = send(&state, import_req(&act_id, &limited_token, &signed_pdf)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "missing signing.perform refused: {body}"
    );
    assert_no_signed_artifact_or_event(&state, &owner, &act_id).await;
}
