//! Multi-signature evidence in the internal preservation package.
//!
//! The question these tests exist to make answerable from an exported package alone is
//! *"who signed ata n.º 7, in what capacity, in what order"*. Before this work the export read only
//! `signed_documents` — one row, the current artifact — and published the signer's raw certificate
//! subject DN and nothing else. A second signer was invisible, and a DN is not a capacity.
//!
//! Two things are asserted here, and they are deliberately kept apart in the exported JSON:
//!
//! - what the **signature** asserts: the signer certificate, its subject DN and the common name
//!   inside it, the CAdES signing time. This is cryptographically bound to the signed bytes.
//! - what **Chancela recorded**: the signer capacity supplied at signing (or resolved through
//!   SCAP), and its verification status. This is product-recorded evidence; the signature says
//!   nothing about it.

use crate::common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::str::FromStr;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, router};
use chancela_core::ActId;
use chancela_store::StoredSignedDocument;
use common::TEST_PASSWORD;
use der::asn1::BitString;
use der::{Encode, asn1::Any};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::macros::datetime;
use tower::ServiceExt;
use uuid::Uuid;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "chancela-api-archive-signatures-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).expect("temp dir created");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct SealedAct {
    book_id: String,
    act_id: String,
    document_id: String,
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
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, bytes)
}

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
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

async fn bootstrap(state: &AppState) -> String {
    let (status, user) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/users")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "username": "archive.signatures.owner",
                    "display_name": "Archive Signatures Owner",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bootstrap user: {user}");
    let user_id = user["id"].as_str().expect("user id");

    let (status, session) = send(
        state,
        Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "user_id": user_id, "password": TEST_PASSWORD }).to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

async fn seal_act(state: &AppState, token: &str) -> SealedAct {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Encosto Estrategico Lda",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadePorQuotas"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity: {entity}");
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    let (status, book) = send(
        state,
        json_req(
            "POST",
            "/v1/books",
            token,
            json!({
                "entity_id": entity_id,
                "kind": "AssembleiaGeral",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Gerente"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    let book_id = book["id"].as_str().expect("book id").to_owned();

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
    let act_id = act["id"].as_str().expect("act id").to_owned();

    let (status, body) = send(
        state,
        json_req(
            "PATCH",
            &format!("/v1/acts/{act_id}"),
            token,
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Sede social",
                "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
                "agenda": [{ "number": 1, "text": "Aprovacao das contas" }],
                "attendance_reference": "Lista de presencas",
                "deliberations": "Aprovadas as contas do exercicio."
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "patch act: {body}");

    for to in [
        "Review",
        "Convened",
        "Deliberated",
        "TextApproved",
        "Signing",
    ] {
        let (status, body) = send(
            state,
            json_req(
                "POST",
                &format!("/v1/acts/{act_id}/advance"),
                token,
                json!({ "to": to }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "advance to {to}: {body}");
    }

    let (status, sealed) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/seal"),
            token,
            json!({
                "manual_signature_original_reference": {
                    "storage_reference": "Arquivo A / Pasta 2026 / Ata teste"
                }
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    let document_id = sealed["document"]["id"]
        .as_str()
        .expect("document id")
        .to_owned();

    SealedAct {
        book_id,
        act_id,
        document_id,
    }
}

fn zip_members(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip readable");
    let mut out = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).expect("zip member");
        let name = file.name().to_owned();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("member readable");
        out.insert(name, buf);
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_act_id(value: &str) -> ActId {
    ActId(Uuid::parse_str(value).expect("act uuid"))
}

/// A syntactically valid X.509 certificate carrying `cn` as its subject common name.
///
/// The key material and the signature are placeholders: nothing in the export path verifies this
/// certificate, it is parsed for its subject. What matters for these tests is that the common name
/// really has to be read out of DER, exactly as it is in production.
fn fixture_cert(cn: &str, serial: u8) -> Vec<u8> {
    let algorithm = AlgorithmIdentifierOwned {
        oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        parameters: Some(Any::null()),
    };
    let name = Name::from_str(&format!("CN={cn},O=Encosto Estrategico Lda,C=PT")).expect("name");
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: algorithm.clone(),
        issuer: Name::from_str("CN=Chancela Test Issuer,C=PT").expect("issuer name"),
        validity: Validity {
            not_before: Time::try_from(std::time::SystemTime::from(datetime!(
                2026-01-01 00:00:00 UTC
            )))
            .expect("not before"),
            not_after: Time::try_from(std::time::SystemTime::from(datetime!(
                2030-01-01 00:00:00 UTC
            )))
            .expect("not after"),
        },
        subject: name,
        subject_public_key_info: SubjectPublicKeyInfoOwned {
            algorithm: algorithm.clone(),
            subject_public_key: BitString::from_bytes(&[0x00; 32]).expect("spki bits"),
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&[0x01; 32]).expect("signature bits"),
    }
    .to_der()
    .expect("certificate der")
}

/// The capacity-evidence JSON the signing routes persist alongside a signature when the operator
/// declares a capacity and SCAP was not consulted.
fn declared_capacity_evidence_json(capacity: &str) -> String {
    json!({
        "requested_provider_capacity": capacity,
        "source": "signature_request",
        "verification_status": "not_checked_by_scap",
        "verification_source": null,
        "verified_at": null,
        "authority_reference": null,
        "status_scope": "declared_capacity_evidence_only",
    })
    .to_string()
}

#[allow(clippy::too_many_arguments)]
fn signature(
    act_id: ActId,
    document_id: &str,
    marker: &str,
    common_name: &str,
    serial: u8,
    capacity_evidence_json: Option<String>,
    signing_time: OffsetDateTime,
    signed_at: OffsetDateTime,
) -> StoredSignedDocument {
    let signed_pdf_bytes = format!("%PDF-1.7\n%{marker}\n").into_bytes();
    StoredSignedDocument {
        act_id,
        document_id: document_id.to_owned(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some(format!("CN={common_name},O=Encosto Estrategico Lda,C=PT")),
        signing_time,
        signed_at,
        signer_cert_der: fixture_cert(common_name, serial),
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: capacity_evidence_json,
        signed_pdf_bytes,
    }
}

fn persist(state: &AppState, signed: &StoredSignedDocument) {
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(signed))
        .expect("signed document persisted");
}

async fn export_members(state: &AppState, token: &str, book_id: &str) -> BTreeMap<String, Vec<u8>> {
    let (status, bytes) = send_bytes(
        state,
        get_req(&format!("/v1/books/{book_id}/archive/package"), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "archive package export");
    zip_members(&bytes)
}

fn member_json(members: &BTreeMap<String, Vec<u8>>, path: &str) -> Value {
    let bytes = members
        .get(path)
        .unwrap_or_else(|| panic!("member {path} present; have {:?}", members.keys()));
    serde_json::from_slice(bytes).expect("member is JSON")
}

fn index_entry(index: &Value, document_id: &str) -> Value {
    index["documents"]
        .as_array()
        .expect("documents array")
        .iter()
        .find(|entry| entry["document_id"] == document_id)
        .unwrap_or_else(|| panic!("index entry for {document_id}"))
        .clone()
}

/// The index exists so the question is answerable without opening every per-document report — which
/// only holds if the two never disagree. The existing tests assert each side against the literals
/// the test itself set up; this one asserts them **against each other**, for every document in the
/// package, so a summary that silently drifts from the chain it summarises is caught even for a
/// document no test enumerates by hand.
#[tokio::test]
async fn the_evidence_index_summary_agrees_with_every_per_document_sidecar() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);

    persist(
        &state,
        &signature(
            act_id,
            &sealed.document_id,
            "first signature",
            "Amelia Marques",
            1,
            Some(declared_capacity_evidence_json("gerente")),
            datetime!(2026-04-01 12:00:00 UTC),
            datetime!(2026-04-01 12:01:00 UTC),
        ),
    );
    persist(
        &state,
        &signature(
            act_id,
            &sealed.document_id,
            "second signature",
            "Joao Nunes",
            2,
            Some(declared_capacity_evidence_json("secretario")),
            datetime!(2026-04-02 09:00:00 UTC),
            datetime!(2026-04-02 09:01:00 UTC),
        ),
    );

    let members = export_members(&state, &token, &sealed.book_id).await;
    let index = member_json(&members, "evidence/index.json");
    let documents = index["documents"].as_array().expect("documents array");
    assert!(
        documents.len() > 1,
        "the package must carry the termo(s) as well as the signed ata: {index:#}"
    );

    let mut signed_documents_seen = 0;
    for entry in documents {
        let document_id = entry["document_id"].as_str().expect("document id");
        let evidence = member_json(&members, &format!("evidence/{document_id}.json"));
        // Book-level documents (the termos) are not act signature targets, so their evidence report
        // carries a stated reason instead of a signature block. The index must then claim nothing:
        // "no signatures" and "not a thing that gets signed" are both honest, but a summary that
        // invented an entry here would be neither.
        let Some(chain) = evidence["signature"]["signatures"].as_array() else {
            assert!(
                evidence["signature"].is_null(),
                "{document_id} has a signature block but no chain: {evidence:#}"
            );
            assert!(
                evidence["reason"].as_str().is_some_and(|r| !r.is_empty()),
                "a document with no signature evidence must say why: {evidence:#}"
            );
            assert_eq!(entry["signature_count"], 0, "{document_id}: {entry:#}");
            assert_eq!(
                entry["signatures"].as_array().map(Vec::len),
                Some(0),
                "{document_id}: {entry:#}"
            );
            continue;
        };

        assert_eq!(
            entry["signature_count"],
            Value::from(chain.len()),
            "index signature_count disagrees with the chain for {document_id}"
        );
        let summary = entry["signatures"]
            .as_array()
            .unwrap_or_else(|| panic!("index entry for {document_id} has a signatures array"));
        assert_eq!(summary.len(), chain.len());
        if !chain.is_empty() {
            signed_documents_seen += 1;
        }

        for (position, (summarised, full)) in summary.iter().zip(chain).enumerate() {
            let context = format!("{document_id} signature #{position}");
            // Ordering is part of the agreement: the summary is `seq` ascending, exactly as the
            // chain is, so a consumer reading the index gets the signing order without re-sorting.
            assert_eq!(summarised["seq"], full["seq"], "{context}: seq");
            assert_eq!(
                summarised["is_current_artifact"], full["is_current_artifact"],
                "{context}: is_current_artifact"
            );
            // Identity in the summary is the *asserted* identity, and capacity the *recorded* one —
            // the index must not flatten the two bases together into one apparent claim.
            for field in ["signer_common_name", "signer_cert_subject", "signing_time"] {
                assert_eq!(
                    summarised[field], full["asserted_by_signature"][field],
                    "{context}: {field} must come from the asserted block"
                );
            }
            assert_eq!(
                summarised["capacity"], full["recorded_by_chancela"]["capacity"],
                "{context}: capacity must come from the recorded block"
            );
        }
    }
    assert_eq!(
        signed_documents_seen, 1,
        "exactly the signed ata carries a chain; the loop above must have actually compared one"
    );
}

/// The gap this whole task exists to close: two gerentes signed the ata, and the exported package
/// must say so — both of them, in signing order, by name and by capacity.
#[tokio::test]
async fn two_signatures_export_with_names_capacities_and_order() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);

    let first = signature(
        act_id,
        &sealed.document_id,
        "first signature",
        "Amelia Marques",
        1,
        Some(declared_capacity_evidence_json("gerente")),
        datetime!(2026-04-01 12:00:00 UTC),
        datetime!(2026-04-01 12:01:00 UTC),
    );
    let second = signature(
        act_id,
        &sealed.document_id,
        "second signature",
        "Joao Nunes",
        2,
        Some(declared_capacity_evidence_json("gerente")),
        datetime!(2026-04-02 09:00:00 UTC),
        datetime!(2026-04-02 09:01:00 UTC),
    );
    persist(&state, &first);
    persist(&state, &second);

    let members = export_members(&state, &token, &sealed.book_id).await;
    let evidence = member_json(&members, &format!("evidence/{}.json", sealed.document_id));

    let signatures = evidence["signature"]["signatures"]
        .as_array()
        .expect("signature chain is exported")
        .clone();
    assert_eq!(
        signatures.len(),
        2,
        "both signatures are exported, not just the current artifact: {evidence:#}"
    );

    assert_eq!(signatures[0]["seq"], 1);
    assert_eq!(signatures[1]["seq"], 2);
    assert_eq!(
        signatures[0]["asserted_by_signature"]["signer_common_name"],
        "Amelia Marques"
    );
    assert_eq!(
        signatures[1]["asserted_by_signature"]["signer_common_name"],
        "Joao Nunes"
    );
    assert_eq!(
        signatures[0]["asserted_by_signature"]["signer_cert_subject"],
        "CN=Amelia Marques,O=Encosto Estrategico Lda,C=PT",
        "the raw DN stays alongside the parsed name"
    );
    assert_eq!(
        signatures[0]["asserted_by_signature"]["signing_time"],
        "2026-04-01T12:00:00Z"
    );
    assert_eq!(
        signatures[1]["asserted_by_signature"]["signing_time"],
        "2026-04-02T09:00:00Z"
    );
    assert_ne!(
        signatures[0]["signed_pdf"]["sha256"], signatures[1]["signed_pdf"]["sha256"],
        "each signature carries the digest of the bytes that signer actually signed"
    );
    assert_eq!(
        signatures[0]["signed_pdf"]["sha256"],
        Value::String(first.signed_pdf_digest.clone()),
        "the superseded signature keeps its own artifact digest"
    );

    for entry in &signatures {
        assert_eq!(
            entry["recorded_by_chancela"]["capacity"], "gerente",
            "capacity is exported: {entry:#}"
        );
        assert_eq!(
            entry["recorded_by_chancela"]["capacity_verification_status"],
            "not_checked_by_scap"
        );
        assert_eq!(
            entry["recorded_by_chancela"]["capacity_present"],
            Value::Bool(true)
        );
    }

    assert_eq!(
        signatures[0]["is_current_artifact"],
        Value::Bool(false),
        "the first signature is not the artifact the package ships"
    );
    assert_eq!(signatures[1]["is_current_artifact"], Value::Bool(true));

    let chain = &evidence["signature"]["signature_chain"];
    assert_eq!(chain["count"], 2);
    assert_eq!(chain["order"], "seq_ascending");
    assert_eq!(chain["basis"], "instrument_signatures");
    assert_eq!(chain["current_artifact_seq"], 2);

    // The index alone must answer the question, without opening the per-document evidence report.
    let index = member_json(&members, "evidence/index.json");
    let entry = index_entry(&index, &sealed.document_id);
    assert_eq!(entry["signature_count"], 2, "index entry: {entry:#}");
    let summary = entry["signatures"].as_array().expect("index signatures");
    assert_eq!(summary.len(), 2);
    assert_eq!(summary[0]["signer_common_name"], "Amelia Marques");
    assert_eq!(summary[0]["capacity"], "gerente");
    assert_eq!(summary[1]["signer_common_name"], "Joao Nunes");
    assert_eq!(summary[1]["capacity"], "gerente");

    // A document with two signatures is still ONE document in the book. The signature history is
    // nested inside the document's entry, never flattened into sibling entries — flattening would
    // make the reading order and the signature order the same axis, and `reading_order` would stop
    // being a dense 1..N over documents. t10-e1-order's ordering invariant is asserted here so a
    // future change that flattens the array fails in this file too, not only in that one.
    let documents = index["documents"].as_array().expect("documents array");
    let reading_orders = documents
        .iter()
        .map(|entry| entry["reading_order"].as_u64().expect("reading order"))
        .collect::<Vec<_>>();
    assert_eq!(
        reading_orders,
        (1..=documents.len() as u64).collect::<Vec<_>>(),
        "reading_order stays a dense 1-based sequence over documents: {reading_orders:?}"
    );
    assert_eq!(
        documents
            .iter()
            .filter(|entry| entry["document_id"] == sealed.document_id.as_str())
            .count(),
        1,
        "the twice-signed ata appears exactly once in the index"
    );
}

/// Capacity and name are not the same kind of claim, and the export must not blur them. The name
/// comes out of the signer certificate, which the signature binds. The capacity is what Chancela
/// was told at signing.
#[tokio::test]
async fn recorded_capacity_is_never_presented_as_asserted_by_the_signature() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);

    persist(
        &state,
        &signature(
            act_id,
            &sealed.document_id,
            "capacity split",
            "Amelia Marques",
            1,
            Some(declared_capacity_evidence_json("gerente")),
            datetime!(2026-04-01 12:00:00 UTC),
            datetime!(2026-04-01 12:01:00 UTC),
        ),
    );

    let members = export_members(&state, &token, &sealed.book_id).await;
    let evidence = member_json(&members, &format!("evidence/{}.json", sealed.document_id));
    let entry = &evidence["signature"]["signatures"][0];

    let asserted = entry["asserted_by_signature"]
        .as_object()
        .expect("asserted block");
    let recorded = entry["recorded_by_chancela"]
        .as_object()
        .expect("recorded block");

    assert!(
        !asserted.contains_key("capacity"),
        "capacity must not appear under what the signature asserts: {asserted:#?}"
    );
    assert!(
        !recorded.contains_key("signer_common_name")
            && !recorded.contains_key("signer_cert_subject"),
        "certificate identity must not appear under what the product recorded: {recorded:#?}"
    );
    assert!(
        asserted["basis"]
            .as_str()
            .is_some_and(|basis| basis.contains("certificate")),
        "the asserted block states its basis: {asserted:#?}"
    );
    assert!(
        recorded["basis"]
            .as_str()
            .is_some_and(|basis| basis.contains("not asserted by the signature")),
        "the recorded block states plainly that the signature does not carry it: {recorded:#?}"
    );
}

/// A signature stored without capacity evidence must say so rather than inventing one.
#[tokio::test]
async fn a_signature_without_recorded_capacity_says_so() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);

    persist(
        &state,
        &signature(
            act_id,
            &sealed.document_id,
            "no capacity",
            "Amelia Marques",
            1,
            None,
            datetime!(2026-04-01 12:00:00 UTC),
            datetime!(2026-04-01 12:01:00 UTC),
        ),
    );

    let members = export_members(&state, &token, &sealed.book_id).await;
    let evidence = member_json(&members, &format!("evidence/{}.json", sealed.document_id));
    let entry = &evidence["signature"]["signatures"][0];

    assert_eq!(
        entry["recorded_by_chancela"]["capacity_present"],
        Value::Bool(false)
    );
    assert_eq!(
        entry["recorded_by_chancela"]["capacity"],
        Value::Null,
        "an unrecorded capacity is null, never a guess: {entry:#}"
    );
    assert_eq!(
        entry["asserted_by_signature"]["signer_common_name"], "Amelia Marques",
        "the certificate identity is still published"
    );

    let index = member_json(&members, "evidence/index.json");
    let summary = index_entry(&index, &sealed.document_id);
    assert_eq!(summary["signatures"][0]["capacity"], Value::Null);
}

/// A single-signature document — the shape every pre-v23 book has — still exports, and exports as
/// one signature at seq 1. The store's own fallback reports it that way and the export must not
/// re-label it.
#[tokio::test]
async fn a_single_signature_document_exports_as_one_signature_at_seq_one() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);

    let only = signature(
        act_id,
        &sealed.document_id,
        "only signature",
        "Amelia Marques",
        1,
        Some(declared_capacity_evidence_json("gerente")),
        datetime!(2026-04-01 12:00:00 UTC),
        datetime!(2026-04-01 12:01:00 UTC),
    );
    persist(&state, &only);

    let members = export_members(&state, &token, &sealed.book_id).await;
    let evidence = member_json(&members, &format!("evidence/{}.json", sealed.document_id));

    let signatures = evidence["signature"]["signatures"]
        .as_array()
        .expect("signature chain");
    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0]["seq"], 1);
    assert_eq!(signatures[0]["is_current_artifact"], Value::Bool(true));
    assert_eq!(
        signatures[0]["signed_pdf"]["sha256"],
        Value::String(only.signed_pdf_digest.clone())
    );

    // The pre-existing single-signature surface is untouched.
    assert_eq!(
        evidence["signature"]["signed_pdf"]["sha256"],
        Value::String(only.signed_pdf_digest.clone())
    );
    assert_eq!(
        evidence["signature"]["signature"]["signer_cert_subject"],
        "CN=Amelia Marques,O=Encosto Estrategico Lda,C=PT"
    );
    assert_eq!(
        evidence["package_profile"],
        "chancela-internal-preservation-package/v1"
    );

    let index = member_json(&members, "evidence/index.json");
    let entry = index_entry(&index, &sealed.document_id);
    assert_eq!(entry["signature_count"], 1);
    assert_eq!(entry["reading_order"], 2, "abertura first, then the ata");
}

/// An unsigned document keeps its existing shape: no chain, no empty scaffolding to misread.
#[tokio::test]
async fn an_unsigned_document_exports_no_signature_chain() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let members = export_members(&state, &token, &sealed.book_id).await;
    let evidence = member_json(&members, &format!("evidence/{}.json", sealed.document_id));

    assert_eq!(evidence["status"], "not_signed");
    assert_eq!(evidence["signature"], Value::Null);

    let index = member_json(&members, "evidence/index.json");
    let entry = index_entry(&index, &sealed.document_id);
    assert_eq!(entry["signature_count"], 0);
    assert_eq!(
        entry["signatures"],
        json!([]),
        "an unsigned document has an empty chain, not a missing key: {entry:#}"
    );
}
