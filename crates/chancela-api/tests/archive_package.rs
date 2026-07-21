//! Archive package evidence reports.
//!
//! These tests exercise the package endpoint through the API router, then inspect the ZIP members
//! directly. The signed case seeds the already-existing `signed_documents` row shape so this stays
//! focused on archive packaging rather than signing routes.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::Path;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_api::{AppState, router};
use chancela_archive::{ArchiveError, PackageFileRole, PreservationLevel, validate_package};
use chancela_authz::{READER_ROLE_ID, RoleAssignment, Scope};
use chancela_core::ActId;
use chancela_signing::{
    DssEvidence, MockProvider, SignOptions, SignerProvider, SigningFamily, attach_pdf_dss,
    sign_pdf_pades, timestamp_pdf_with_url,
};
use chancela_store::{StoredDocument, StoredSignedDocument};
use common::TEST_PASSWORD;
use common::tsa_http::MockTsaServer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::macros::datetime;
use tower::ServiceExt;
use uuid::Uuid;

const OCSP_DER_FIXTURE: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
const CRL_DER_FIXTURE: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];
const DOC_TIMESTAMP_FIXTURE_PDF: &[u8] = include_bytes!(
    "../../../docs/fixtures/validator-corpus/cases/future-doctimestamp/input/future-doctimestamp.pdf"
);

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("chancela-api-archive-package-{}", Uuid::new_v4()));
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

struct SealedCondominiumAbsentOwnerAct {
    book_id: String,
    act_id: String,
    ata_document_id: String,
    communication_document_id: String,
}

struct SealedGeneratedConveningNoticeAct {
    book_id: String,
    act_id: String,
    ata_document_id: String,
    notice_document_id: String,
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

async fn send_bytes(state: &AppState, req: Request<Body>) -> (StatusCode, String, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, ctype, bytes)
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
                    "username": "archive.owner",
                    "display_name": "Archive Owner",
                    "password": TEST_PASSWORD,
                })
                .to_string(),
            ))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create owner: {user}");
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
                "name": "Encosto Estrategico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima"
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
                "required_signatories": ["Administrador"]
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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A / Pasta 2026 / Ata teste" } })),
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

async fn seal_condominium_absent_owner_act(
    state: &AppState,
    token: &str,
) -> SealedCondominiumAbsentOwnerAct {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Condominio Alameda Um",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "Condominio"
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
                "kind": "Condominio",
                "purpose": "livro de atas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"]
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
            json!({
                "book_id": book_id,
                "title": "Ata da assembleia de condóminos",
                "channel": "Physical"
            }),
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
                "place": "Hall do prédio",
                "agenda": [{ "number": 1, "text": "Orçamento anual" }],
                "attendance_reference": "Folha de presenças",
                "deliberations": "Aprovado o orçamento anual.",
                "deliberation_items": [{
                    "agenda_number": 1,
                    "text": "Aprovado o orçamento anual.",
                    "vote": { "type": "Recorded", "em_favor": 600, "contra": 0, "abstencoes": 0 },
                    "statements": []
                }],
                "attendees": [
                    {
                        "name": "Fração A",
                        "quality": "CondoOwner",
                        "presence": "InPerson",
                        "weight": { "Permilage": 600 }
                    },
                    {
                        "name": "Fração B",
                        "quality": "CondoOwner",
                        "presence": "Absent",
                        "weight": { "Permilage": 400 }
                    }
                ]
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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A / Pasta 2026 / Ata teste" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    let ata_document_id = sealed["document"]["id"]
        .as_str()
        .expect("ata document id")
        .to_owned();
    assert_eq!(
        sealed["document"]["template_id"],
        "condominio-ata-assembleia/v1"
    );

    let (status, generated_docs) = send(
        state,
        get_req(&format!("/v1/acts/{act_id}/documents/generated"), token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "generated documents: {generated_docs}"
    );
    let communication_document_id = generated_docs
        .as_array()
        .expect("generated documents")
        .iter()
        .find(|doc| doc["template_id"].as_str() == Some("condominio-comunicacao-ausentes/v1"))
        .and_then(|doc| doc["id"].as_str())
        .unwrap_or_else(|| panic!("absent-owner communication missing: {generated_docs}"))
        .to_owned();

    SealedCondominiumAbsentOwnerAct {
        book_id,
        act_id,
        ata_document_id,
        communication_document_id,
    }
}

async fn seal_generated_convening_notice_act(
    state: &AppState,
    token: &str,
) -> SealedGeneratedConveningNoticeAct {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Encosto Estrategico, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima"
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
                "required_signatories": ["Administrador"]
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
            json!({
                "book_id": book_id,
                "title": "Ata da AG anual convocada",
                "channel": "Physical"
            }),
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
                "deliberations": "Aprovadas as contas do exercicio.",
                "convening": {
                    "convener": "Ana Presidente",
                    "convener_capacity": "Administrator",
                    "dispatch_date": "2026-03-01",
                    "antecedence_days": 21,
                    "channel": "Email",
                    "evidence_reference": "doc:convocatoria-2026-03-01",
                    "recipients": [
                        { "name": "Ana Sócia", "contact": "ana@example.test", "channel": "Email", "reference": "MSG-1" },
                        { "name": "Bruno Sócio", "contact": "bruno@example.test", "channel": "Email", "reference": "MSG-2" }
                    ]
                }
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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({ "manual_signature_original_reference": { "storage_reference": "Arquivo A / Pasta 2026 / Ata convocada" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");
    let ata_document_id = sealed["document"]["id"]
        .as_str()
        .expect("ata document id")
        .to_owned();

    let (status, notice) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/acts/{act_id}/document/generate?template_id=csc-convocatoria-ag/v1"),
            token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "generated notice: {notice}");
    assert_eq!(notice["template_id"], "csc-convocatoria-ag/v1");
    assert_eq!(
        notice["dispatch_evidence_status"]["status"],
        "required_pending"
    );
    let notice_document_id = notice["id"]
        .as_str()
        .expect("notice document id")
        .to_owned();

    SealedGeneratedConveningNoticeAct {
        book_id,
        act_id,
        ata_document_id,
        notice_document_id,
    }
}

async fn open_empty_archive_book(state: &AppState, token: &str) -> String {
    let (status, entity) = send(
        state,
        json_req(
            "POST",
            "/v1/entities",
            token,
            json!({
                "name": "Arquivo Sem Atas, S.A.",
                "nipc": "503004642",
                "seat": "Lisboa",
                "kind": "SociedadeAnonima"
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
                "purpose": "livro de atas sem atas arquivadas",
                "opening_date": "2026-01-15",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "book: {book}");
    book["id"].as_str().expect("book id").to_owned()
}

async fn record_absent_owner_dispatch_evidence(
    state: &AppState,
    token: &str,
    document_id: &str,
    operator_note: &str,
) -> Value {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/documents/generated/{document_id}/dispatch-evidence"),
            token,
            json!({
                "actor": "archive.operator",
                "dispatched_at": "2026-04-01T10:00:00Z",
                "channel": "RegisteredLetter",
                "reference": "RR123456789PT",
                "recipients": ["Fração B"],
                "evidence_reference": "archive:dispatch-proof-1",
                "operator_note": operator_note
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "dispatch evidence: {body}");
    body
}

async fn record_generated_convening_notice_dispatch_evidence(
    state: &AppState,
    token: &str,
    document_id: &str,
    operator_note: &str,
) -> Value {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/documents/generated/{document_id}/dispatch-evidence"),
            token,
            json!({
                "actor": "archive.operator",
                "dispatched_at": "2026-03-01T09:00:00Z",
                "channel": "Email",
                "reference": "MSG-1",
                "recipients": ["Ana Sócia", "Bruno Sócio"],
                "evidence_reference": "archive:generated-convening-notice-dispatch",
                "operator_note": operator_note
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "dispatch evidence: {body}");
    body
}

async fn archive_package_bytes(state: &AppState, book_id: &str, token: &str) -> Vec<u8> {
    archive_package_bytes_at(
        state,
        &format!("/v1/books/{book_id}/archive/package"),
        token,
    )
    .await
}

async fn archive_package_bytes_at(state: &AppState, uri: &str, token: &str) -> Vec<u8> {
    let (status, content_type, bytes) = send_bytes(state, get_req(uri, token)).await;
    assert_eq!(status, StatusCode::OK, "archive package status");
    assert_eq!(content_type, "application/zip");
    assert!(!bytes.is_empty(), "archive package has bytes");
    bytes
}

fn local_dglab_interchange_manifest_uri(book_id: &str) -> String {
    format!("/v1/books/{book_id}/archive/local-dglab-interchange-manifest")
}

async fn local_dglab_interchange_manifest_bytes(
    state: &AppState,
    book_id: &str,
    token: &str,
) -> Vec<u8> {
    let (status, content_type, bytes) = send_bytes(
        state,
        get_req(&local_dglab_interchange_manifest_uri(book_id), token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "local DGLAB manifest status");
    assert_eq!(content_type, "application/json");
    assert!(!bytes.is_empty(), "local DGLAB manifest has bytes");
    bytes
}

fn zip_members(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip readable");
    let mut out = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).expect("zip member");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).expect("member bytes");
        out.insert(file.name().to_owned(), bytes);
    }
    out
}

fn write_zip_entries(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central_directory = Vec::new();
    for (name, bytes) in entries {
        let offset = out.len() as u32;
        let name_bytes = name.as_bytes();
        let crc = crc32(bytes);
        append_u32(&mut out, 0x0403_4b50);
        append_u16(&mut out, 20);
        append_u16(&mut out, 0);
        append_u16(&mut out, 0);
        append_u16(&mut out, 0);
        append_u16(&mut out, 0x0021);
        append_u32(&mut out, crc);
        append_u32(&mut out, bytes.len() as u32);
        append_u32(&mut out, bytes.len() as u32);
        append_u16(&mut out, name_bytes.len() as u16);
        append_u16(&mut out, 0);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(bytes);

        append_u32(&mut central_directory, 0x0201_4b50);
        append_u16(&mut central_directory, 20);
        append_u16(&mut central_directory, 20);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0x0021);
        append_u32(&mut central_directory, crc);
        append_u32(&mut central_directory, bytes.len() as u32);
        append_u32(&mut central_directory, bytes.len() as u32);
        append_u16(&mut central_directory, name_bytes.len() as u16);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0);
        append_u16(&mut central_directory, 0);
        append_u32(&mut central_directory, 0);
        append_u32(&mut central_directory, offset);
        central_directory.extend_from_slice(name_bytes);
    }

    let central_directory_offset = out.len() as u32;
    let central_directory_size = central_directory.len() as u32;
    out.extend_from_slice(&central_directory);
    append_u32(&mut out, 0x0605_4b50);
    append_u16(&mut out, 0);
    append_u16(&mut out, 0);
    append_u16(&mut out, entries.len() as u16);
    append_u16(&mut out, entries.len() as u16);
    append_u32(&mut out, central_directory_size);
    append_u32(&mut out, central_directory_offset);
    append_u16(&mut out, 0);
    out
}

fn append_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn write_zip_members(members: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut entries = Vec::new();
    if let Some(manifest) = members.get("manifest.json") {
        entries.push(("manifest.json".to_owned(), manifest.clone()));
    }
    entries.extend(
        members
            .iter()
            .filter(|(name, _)| name.as_str() != "manifest.json")
            .map(|(name, bytes)| (name.clone(), bytes.clone())),
    );
    write_zip_entries(&entries)
}

fn tamper_manifest_json(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut members = zip_members(bytes);
    let manifest_bytes = members.get("manifest.json").expect("manifest member");
    let mut manifest: Value =
        serde_json::from_slice(manifest_bytes).expect("manifest is JSON before tamper");
    mutate(&mut manifest);
    members.insert(
        "manifest.json".to_owned(),
        serde_json::to_vec_pretty(&manifest).expect("tampered manifest JSON"),
    );
    write_zip_members(&members)
}

fn member_json(members: &BTreeMap<String, Vec<u8>>, path: &str) -> Value {
    serde_json::from_slice(
        members
            .get(path)
            .unwrap_or_else(|| panic!("missing zip member {path}")),
    )
    .unwrap_or_else(|e| panic!("{path} is valid JSON: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn data_dir_paths(root: &Path) -> BTreeSet<String> {
    fn visit(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        let mut entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read data dir {}: {e}", dir.display()))
            .map(|entry| entry.expect("data dir entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .expect("path below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel);
            }
        }
    }

    let mut out = BTreeSet::new();
    visit(root, root, &mut out);
    out
}

fn data_dir_contains_subslice(root: &Path, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut entries = vec![root.to_owned()];
    while let Some(path) = entries.pop() {
        if path.is_dir() {
            entries.extend(
                std::fs::read_dir(&path)
                    .unwrap_or_else(|e| panic!("read data dir {}: {e}", path.display()))
                    .map(|entry| entry.expect("data dir entry").path()),
            );
        } else if path.is_file() {
            let bytes = std::fs::read(&path).expect("data dir file bytes");
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return true;
            }
        }
    }
    false
}

fn external_validator_metadata_value(case_id: &str, family: &str, document_sha256: &str) -> Value {
    json!({
        "schema": "chancela-external-validator-report-evidence/v1",
        "evidence_kind": "external_validator_report_metadata",
        "legal_validity_claimed": false,
        "evidence_scope": {
            "kind": "external_validator_report",
            "technical_only": true,
            "legal_validity_assessment": "not_assessed",
            "claim": "technical_validator_evidence_only"
        },
        "case_id": case_id,
        "source_sidecar": {
            "schema": "chancela-external-validator-sidecar/v1",
            "path": format!("cases/{case_id}/expected/{family}.json")
        },
        "validator": {
            "family": family,
            "name": "Fixture validator",
            "version": "1.0",
            "run_status": "recorded",
            "run_at": "2026-07-10T00:00:00Z",
            "operator": "operator@example.test",
            "environment": "test",
            "command": "validator --fixture"
        },
        "document": {
            "path": format!("cases/{case_id}/input/{case_id}.pdf"),
            "sha256": document_sha256,
            "bytes": 1
        },
        "report": {
            "path": format!("cases/{case_id}/reports/{family}.json"),
            "sidecar_path": format!("../reports/{family}.json"),
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "bytes": 2,
            "content_type": "application/json",
            "source_filename": format!("{family}.json"),
            "captured_at": "2026-07-10T00:00:00Z",
            "preserved_at": "2026-07-10T00:00:00Z",
            "preserved_by": "operator@example.test",
            "preservation_action": "copied_to_corpus"
        },
        "transcription": {
            "status": "raw_report_only",
            "summary": "Raw report metadata preserved.",
            "findings_available": false
        },
        "archive_attachment": {
            "role": "technical_external_validator_report_metadata",
            "content_type": "application/json",
            "suggested_path": format!("evidence/external-validators/{case_id}-{family}.json")
        },
        "evidence_indexing": {
            "status_scope": "technical_metadata_only",
            "archive_package": {
                "index_path": "evidence/index.json",
                "indexed_path_prefix": "evidence/external-validators/",
                "indexed_path_pattern": "evidence/external-validators/{case_id}-{validator_family}.json"
            },
            "document_bundle": {
                "index_json_pointer": "/validation_report/evidence_index/external_validator_reports",
                "archive_path_prefix": "evidence/external-validators/",
                "archive_path_pattern": "evidence/external-validators/{case_id}-{validator_family}.json"
            }
        }
    })
}

fn external_validator_metadata_bytes(
    case_id: &str,
    family: &str,
    document_sha256: &str,
) -> Vec<u8> {
    external_validator_metadata_value(case_id, family, document_sha256)
        .to_string()
        .into_bytes()
}

fn external_validator_metadata_with_raw_report_bytes(
    case_id: &str,
    family: &str,
    document_sha256: &str,
) -> (Vec<u8>, Vec<u8>, String) {
    let raw_report =
        br#"{"report_kind":"external_validator_raw_report","status":"technical"}"#.to_vec();
    let raw_report_sha256 = sha256_hex(&raw_report);
    let mut metadata = external_validator_metadata_value(case_id, family, document_sha256);
    metadata["raw_report"] = json!({
        "content_type": "application/json",
        "sha256": raw_report_sha256,
        "bytes": raw_report.len(),
        "source_filename": format!("{family}-raw.json"),
        "suggested_path": format!(
            "evidence/external-validators/{case_id}-{family}-raw-report.json"
        ),
        "content_base64": B64.encode(&raw_report)
    });
    (
        metadata.to_string().into_bytes(),
        raw_report,
        raw_report_sha256,
    )
}

fn parse_act_id(value: &str) -> ActId {
    ActId(Uuid::parse_str(value).expect("act uuid"))
}

fn stored_document(state: &AppState, act_id: ActId, document_id: &str) -> StoredDocument {
    state
        .store
        .as_ref()
        .expect("store")
        .documents_for_act(act_id)
        .expect("documents for act")
        .into_iter()
        .find(|doc| doc.id == document_id)
        .unwrap_or_else(|| panic!("document {document_id} for {act_id}"))
}

fn upsert_document(state: &AppState, document: &StoredDocument) {
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_document(document))
        .expect("document upserted");
}

async fn ledger_events(state: &AppState, token: &str) -> Value {
    let (status, body) = send(state, get_req("/v1/ledger/events?limit=1000", token)).await;
    assert_eq!(status, StatusCode::OK, "ledger events: {body}");
    body
}

async fn reader_token_without_book_export(state: &AppState, owner_token: &str) -> String {
    let (status, user) = send(
        state,
        json_req(
            "POST",
            "/v1/users",
            owner_token,
            json!({
                "username": format!("archive.reader.{}", Uuid::new_v4()),
                "display_name": "Archive Reader",
                "password": TEST_PASSWORD,
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create reader: {user}");
    let user_id = user["id"].as_str().expect("reader id");
    {
        let mut users = state.users.write().await;
        let user = users
            .get_mut(&chancela_api::UserId(
                Uuid::parse_str(user_id).expect("reader uuid"),
            ))
            .expect("reader user exists");
        user.role_assignments = vec![RoleAssignment::new(READER_ROLE_ID, Scope::Global)];
    }

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
    assert_eq!(status, StatusCode::OK, "open reader session: {session}");
    session["token"].as_str().expect("reader token").to_owned()
}

async fn close_book(state: &AppState, token: &str, book_id: &str) {
    let (status, body) = send(
        state,
        json_req(
            "POST",
            &format!("/v1/books/{book_id}/close"),
            token,
            json!({
                "reason": "BookFull",
                "closing_date": "2026-12-31",
                "required_signatories": ["Administrador"]
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "close book: {body}");
    assert_eq!(body["state"], "Closed");
}

async fn assert_failed_package_validation_is_read_only(
    state: &AppState,
    token: &str,
    book_id: &str,
    before_ledger: &Value,
    before_package: &[u8],
) {
    let after_ledger = ledger_events(state, token).await;
    assert_eq!(
        before_ledger, &after_ledger,
        "failed package validation must not append ledger events"
    );
    let after_package = archive_package_bytes(state, book_id, token).await;
    assert_eq!(
        before_package,
        after_package.as_slice(),
        "failed package validation must not rewrite archive inputs"
    );
}

#[tokio::test]
async fn archive_package_legal_hold_marks_manifest_and_blocks_disposal() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let reason = "litigation preservation request";
    let encoded_reason = "litigation%20preservation%20request";

    let bytes = archive_package_bytes_at(
        &state,
        &format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason={}",
            sealed.book_id, encoded_reason
        ),
        &token,
    )
    .await;

    let manifest = validate_package(&bytes).expect("archive package validates");
    assert!(manifest.retention.legal_hold);
    assert!(
        !manifest.retention.is_disposable(),
        "legal hold must block retention-driven disposal"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == "evidence/legal-hold.json"
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "legal hold evidence is declared in manifest: {manifest:?}"
    );

    let members = zip_members(&bytes);
    let report = member_json(&members, "evidence/legal-hold.json");
    assert_eq!(report["report_kind"], "retention_legal_hold_evidence");
    assert_eq!(report["status"], "active");
    assert_eq!(report["legal_hold"], true);
    assert_eq!(report["reason"], reason);
    assert_eq!(report["scope"], "book_archive_package_export");
    assert_eq!(
        report["persistence"],
        "export_time_only; this endpoint does not persist legal-hold state"
    );
}

#[tokio::test]
async fn archive_package_legal_hold_rejects_missing_or_empty_reason() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    for uri in [
        format!(
            "/v1/books/{}/archive/package?legal_hold=true",
            sealed.book_id
        ),
        format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason=%20%20",
            sealed.book_id
        ),
    ] {
        let (status, body) = send(&state, get_req(&uri, &token)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(
            body["error"],
            "legal_hold_reason is required when legal_hold=true"
        );
    }
}

#[tokio::test]
async fn persisted_book_legal_hold_round_trips_and_archive_uses_it() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let reason = "court preservation order";

    let (status, hold) = send(
        &state,
        json_req(
            "PUT",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "reason": reason, "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set legal hold: {hold}");
    assert_eq!(hold["legal_hold"], true);
    assert_eq!(hold["reason"], reason);
    assert_eq!(hold["actor"], "archive.owner");
    assert_eq!(hold["operator_workflow"]["status"], "blocked_by_legal_hold");
    assert_eq!(hold["operator_workflow"]["disposal_review_blocked"], true);
    assert_eq!(
        hold["operator_workflow"]["destructive_disposal_completed"],
        false
    );
    assert_eq!(hold["operator_workflow"]["disposal_approved"], false);
    assert_eq!(hold["operator_workflow"]["legal_compliance_claimed"], false);
    assert!(
        hold["operator_workflow"]["review_note"]
            .as_str()
            .is_some_and(|note| note.contains("Local operator workflow/status evidence only"))
    );
    assert!(
        hold["set_at"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let persisted = state.store.as_ref().expect("store").load().expect("load");
    let book_id = Uuid::parse_str(&sealed.book_id).expect("book uuid");
    let stored_hold = persisted
        .books
        .get(&chancela_core::BookId(book_id))
        .and_then(|book| book.legal_hold.as_ref())
        .expect("legal hold persisted");
    assert_eq!(stored_hold.reason, reason);
    assert_eq!(stored_hold.actor, "archive.owner");

    let (status, hold) = send(
        &state,
        get_req(&format!("/v1/books/{}/legal-hold", sealed.book_id), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "read legal hold: {hold}");
    assert_eq!(hold["legal_hold"], true);
    assert_eq!(hold["reason"], reason);
    assert_eq!(
        hold["operator_workflow"]["next_step"],
        "Keep disposal blocked and review the legal-hold evidence in a separate authorized workflow before any retention action."
    );

    let bytes = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&bytes).expect("archive package validates");
    assert!(manifest.retention.legal_hold);
    assert!(!manifest.retention.is_disposable());
    let members = zip_members(&bytes);
    let report = member_json(&members, "evidence/legal-hold.json");
    assert_eq!(report["report_kind"], "retention_legal_hold_evidence");
    assert_eq!(report["status"], "active");
    assert_eq!(report["legal_hold"], true);
    assert_eq!(report["reason"], reason);
    assert_eq!(report["actor"], "archive.owner");
    assert_eq!(report["persistence"], "persisted_book_state");
    assert!(
        report["set_at"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let (status, hold) = send(
        &state,
        json_req(
            "DELETE",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "clear legal hold: {hold}");
    assert_eq!(hold["legal_hold"], false);
    assert!(hold["reason"].is_null());
    assert_eq!(hold["operator_workflow"]["status"], "advisory_only");
    assert_eq!(hold["operator_workflow"]["disposal_review_blocked"], false);
    let persisted = state.store.as_ref().expect("store").load().expect("load");
    assert!(
        persisted
            .books
            .get(&chancela_core::BookId(book_id))
            .and_then(|book| book.legal_hold.as_ref())
            .is_none(),
        "legal hold cleared durably"
    );
}

#[tokio::test]
async fn disposal_status_blocks_active_persisted_legal_hold() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let (status, hold) = send(
        &state,
        json_req(
            "PUT",
            &format!("/v1/books/{}/legal-hold", sealed.book_id),
            &token,
            json!({ "reason": "court order", "actor": "records.manager" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "set legal hold: {hold}");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "disposal status: {body}");
    assert_eq!(body["book_id"], sealed.book_id);
    assert_eq!(body["book_state"], "Open");
    assert_eq!(body["eligible"], false);
    assert_eq!(body["blocked"], true);
    assert_eq!(body["active_persisted_legal_hold"], true);
    assert_eq!(body["export_time_legal_hold_persisted"], false);
    assert_eq!(body["operator_workflow"]["status"], "blocked");
    assert_eq!(
        body["operator_workflow"]["destructive_disposal_completed"],
        false
    );
    assert_eq!(body["operator_workflow"]["disposal_approved"], false);
    assert_eq!(body["operator_workflow"]["legal_compliance_claimed"], false);
    assert_eq!(body["operator_workflow"]["dry_run_status_only"], true);
    assert!(
        body["reasons"].as_array().is_some_and(|reasons| reasons
            .iter()
            .any(|reason| reason["code"] == "active_persisted_legal_hold"
                && reason["blocking"] == true)),
        "legal hold reason is reported: {body}"
    );

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": true }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "dry-run disposal is blocked by hold: {body}"
    );
}

#[tokio::test]
async fn disposal_dry_run_allowed_without_persisted_hold_after_export_time_hold() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let _package = archive_package_bytes_at(
        &state,
        &format!(
            "/v1/books/{}/archive/package?legal_hold=true&legal_hold_reason=export%20only",
            sealed.book_id
        ),
        &token,
    )
    .await;

    close_book(&state, &token, &sealed.book_id).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": true }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "dry-run disposal: {body}");
    assert_eq!(body["dry_run"], true);
    assert_eq!(body["status"]["eligible"], true);
    assert_eq!(body["status"]["blocked"], false);
    assert_eq!(body["status"]["active_persisted_legal_hold"], false);
    assert_eq!(body["status"]["export_time_legal_hold_persisted"], false);
    assert_eq!(
        body["status"]["reasons"].as_array().expect("reasons").len(),
        0
    );
    assert!(
        body["status"]["signed_evidence"]["documents_total"]
            .as_u64()
            .is_some_and(|count| count >= 1),
        "document evidence summary is present: {body}"
    );
    assert_eq!(
        body["would_delete"]["package_profile"],
        "chancela-internal-preservation-package/v1"
    );
    assert!(
        body["would_delete"]["package_members"]
            .as_array()
            .is_some_and(|members| members
                .iter()
                .any(|member| member["path"] == format!("documents/{}.pdf", sealed.document_id))),
        "dry-run manifest names package members: {body}"
    );
}

#[tokio::test]
async fn disposal_non_dry_run_is_refused_without_deleting_data() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    close_book(&state, &token, &sealed.book_id).await;

    let (status, body) = send(
        &state,
        json_req(
            "POST",
            &format!("/v1/books/{}/archive/disposal", sealed.book_id),
            &token,
            json!({ "dry_run": false }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "non-dry-run without policy refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("retention_policy_id is required")),
        "refusal tells clients to provide retention policy evidence: {body}"
    );

    let (status, book) = send(
        &state,
        get_req(&format!("/v1/books/{}", sealed.book_id), &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "book still exists: {book}");
    assert_eq!(book["id"], sealed.book_id);
}

#[tokio::test]
async fn archive_package_rejects_stored_pdf_digest_mismatch_without_mutating_ledger() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let before = ledger_events(&state, &token).await;

    let mut document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    document.pdf_digest = "0".repeat(64);
    upsert_document(&state, &document);

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "corrupt export: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("pdf_digest mismatch")),
        "digest mismatch is explicit: {body}"
    );

    let after = ledger_events(&state, &token).await;
    assert_eq!(before, after, "failed archive validation is read-only");
}

#[tokio::test]
async fn archive_package_validation_rejects_missing_manifest_entries_without_mutating_state() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let before_ledger = ledger_events(&state, &token).await;
    let document_path = format!("documents/{}.pdf", sealed.document_id);

    let mut members = zip_members(&package);
    members.remove("manifest.json");
    let missing_manifest = write_zip_members(&members);
    assert_eq!(
        validate_package(&missing_manifest),
        Err(ArchiveError::InvalidPackage(
            "missing manifest.json".to_owned()
        ))
    );

    let mut members = zip_members(&package);
    members.remove(&document_path);
    let missing_member = write_zip_members(&members);
    assert_eq!(
        validate_package(&missing_member),
        Err(ArchiveError::MissingArtifact(document_path.clone()))
    );

    let missing_manifest_entry = tamper_manifest_json(&package, |manifest| {
        let files = manifest["files"].as_array_mut().expect("manifest files");
        let removed_index = files
            .iter()
            .position(|file| file["path"] == document_path)
            .expect("document manifest entry");
        files.remove(removed_index);
        let total_byte_len = files
            .iter()
            .map(|file| file["byte_len"].as_u64().expect("byte_len"))
            .sum::<u64>();
        manifest["preservation_interchange"]["fixity"]["file_count"] = json!(files.len());
        manifest["preservation_interchange"]["fixity"]["total_byte_len"] = json!(total_byte_len);
    });
    assert!(
        matches!(
            validate_package(&missing_manifest_entry),
            Err(ArchiveError::InvalidPackage(message))
                if message == format!("untracked member {document_path}")
        ),
        "manifest that omits an existing member must be rejected"
    );

    assert_failed_package_validation_is_read_only(
        &state,
        &token,
        &sealed.book_id,
        &before_ledger,
        &package,
    )
    .await;
}

#[tokio::test]
async fn archive_package_validation_rejects_checksum_path_and_duplicate_tampering() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let before_ledger = ledger_events(&state, &token).await;
    let document_path = format!("documents/{}.pdf", sealed.document_id);

    let mut members = zip_members(&package);
    let document_bytes = members.get_mut(&document_path).expect("document member");
    let last = document_bytes.last_mut().expect("document bytes");
    *last ^= 0x01;
    let checksum_mismatch = write_zip_members(&members);
    assert!(
        matches!(
            validate_package(&checksum_mismatch),
            Err(ArchiveError::ChecksumMismatch { path, .. }) if path == document_path
        ),
        "content tampering must be reported as a checksum mismatch"
    );

    for unsafe_path in ["../escape.pdf", "/absolute.pdf", "C:/absolute.pdf"] {
        let path_tampered = tamper_manifest_json(&package, |manifest| {
            let files = manifest["files"].as_array_mut().expect("manifest files");
            let document_file = files
                .iter_mut()
                .find(|file| file["path"] == document_path)
                .expect("document manifest entry");
            document_file["path"] = json!(unsafe_path);
        });
        assert_eq!(
            validate_package(&path_tampered),
            Err(ArchiveError::InvalidPath(unsafe_path.to_owned())),
            "unsafe manifest path {unsafe_path} must be rejected"
        );
    }

    let duplicate_path = tamper_manifest_json(&package, |manifest| {
        let files = manifest["files"].as_array_mut().expect("manifest files");
        let document_index = files
            .iter()
            .position(|file| file["path"] == document_path)
            .expect("document manifest entry");
        files.insert(document_index + 1, files[document_index].clone());
    });
    assert_eq!(
        validate_package(&duplicate_path),
        Err(ArchiveError::DuplicatePath(document_path))
    );

    assert_failed_package_validation_is_read_only(
        &state,
        &token,
        &sealed.book_id,
        &before_ledger,
        &package,
    )
    .await;
}

#[tokio::test]
async fn archive_package_rejects_missing_preserved_pdf_bytes() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let mut document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    document.pdf_bytes.clear();
    document.pdf_digest = sha256_hex(&document.pdf_bytes);
    upsert_document(&state, &document);

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "missing PDF bytes: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("no preserved PDF bytes")),
        "missing content is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_duplicate_document_ids_before_manifest_build() {
    let dir = TempDir::new();
    let mut state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let book_owner = parse_act_id(&sealed.book_id);
    state.store = None;

    {
        let mut documents = state.documents.write().await;
        let book_document = documents
            .get_mut(&book_owner)
            .expect("book opening document exists");
        book_document.id = sealed.document_id.clone();
    }

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplicate doc id: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("appears more than once")),
        "duplicate document id is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_path_traversal_like_document_id_metadata() {
    let dir = TempDir::new();
    let mut state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let book_owner = parse_act_id(&sealed.book_id);
    state.store = None;

    {
        let mut documents = state.documents.write().await;
        let book_document = documents
            .get_mut(&book_owner)
            .expect("book opening document exists");
        book_document.id = "../metadata.json".to_owned();
    }

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "path-like doc id: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("stored document id is not a UUID")),
        "path-like id is rejected before it can become a package path: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_signed_metadata_for_the_wrong_document() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);
    let wrong_document_id = Uuid::new_v4().to_string();
    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: wrong_document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:01:00 UTC),
        signer_cert_der: b"fixture signer certificate DER".to_vec(),
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "wrong signed doc: {body}");
    assert!(
        body["error"].as_str().is_some_and(|error| {
            error.contains("references document")
                && error.contains(&wrong_document_id)
                && error.contains(&sealed.document_id)
        }),
        "wrong signed document link is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_signed_metadata_with_impossible_dates() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);
    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:01:00 UTC),
        signed_at: datetime!(2026-04-01 12:00:00 UTC),
        signer_cert_der: b"fixture signer certificate DER".to_vec(),
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "impossible dates: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("signed_at before signing_time")),
        "impossible signature chronology is explicit: {body}"
    );
}

#[tokio::test]
async fn archive_package_rejects_incomplete_signature_evidence_without_mutating_state() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let before_ledger = ledger_events(&state, &token).await;
    let act_id = parse_act_id(&sealed.act_id);
    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_bytes),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:01:00 UTC),
        signer_cert_der: b"fixture signer certificate DER".to_vec(),
        timestamp_token_der: Some(Vec::new()),
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let (status, body) = send(
        &state,
        get_req(
            &format!("/v1/books/{}/archive/package", sealed.book_id),
            &token,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "empty timestamp: {body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("empty timestamp token")),
        "invalid signature evidence state is explicit: {body}"
    );
    let after_ledger = ledger_events(&state, &token).await;
    assert_eq!(
        before_ledger, after_ledger,
        "failed export must not append ledger events"
    );
    let persisted = state
        .store
        .as_ref()
        .expect("store")
        .signed_document_for_act(act_id)
        .expect("signed lookup")
        .expect("signed document still present");
    assert_eq!(
        persisted.timestamp_token_der,
        Some(Vec::new()),
        "failed export must not rewrite invalid signature evidence"
    );
}

#[tokio::test]
async fn archive_package_reports_unsigned_documents_without_placeholder_pdf_accessibility() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let first = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let second = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(first, second, "archive output stays deterministic");

    let manifest = validate_package(&first).expect("archive package validates");
    let preservation = &manifest.preservation_interchange;
    assert_eq!(
        preservation.profile,
        "chancela-internal-dglab-aligned-preservation-metadata/v1"
    );
    assert!(!preservation.official_dglab_interchange);
    assert!(!preservation.dglab_certification_claimed);
    assert_eq!(preservation.producer.name, "Encosto Estrategico, S.A.");
    assert_eq!(preservation.producer.system, "Chancela");
    assert_eq!(
        preservation.package_type,
        "chancela-internal-preservation-package"
    );
    assert_eq!(preservation.package_version, "1");
    assert_eq!(preservation.preservation_level, PreservationLevel::Managed);
    assert!(preservation.classification.scheme.is_none());
    assert!(preservation.classification.code.is_none());
    assert!(preservation.classification.title.is_none());
    assert!(preservation.classification.sensitivity.is_none());
    assert_eq!(preservation.retention, manifest.retention);
    assert_eq!(
        preservation.rights.holder.as_deref(),
        Some("Encosto Estrategico, S.A.")
    );
    assert_eq!(
        preservation.rights.access_note.as_deref(),
        Some("Chancela internal preservation package")
    );
    assert_eq!(preservation.languages, vec!["pt-PT".to_owned()]);
    assert_eq!(preservation.provenance.source_system, "Chancela");
    assert_eq!(
        preservation.provenance.record_count,
        manifest.provenance.len()
    );
    assert_eq!(preservation.fixity.algorithm, "sha256");
    assert_eq!(preservation.fixity.manifest_path, "manifest.json");
    assert_eq!(preservation.fixity.file_count, manifest.files.len());
    let total_byte_len: u64 = manifest.files.iter().map(|file| file.byte_len).sum();
    assert_eq!(preservation.fixity.total_byte_len, total_byte_len);

    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    let pdf_accessibility_path = format!("evidence/pdf-accessibility/{}.json", sealed.document_id);
    let evidence_file = manifest
        .files
        .iter()
        .find(|file| file.path == evidence_path)
        .expect("act evidence report in manifest");
    assert_eq!(evidence_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(evidence_file.content_type, "application/json");
    assert_eq!(
        evidence_file.act_id.map(|id| id.to_string()).as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(
        evidence_file
            .document_id
            .map(|id| id.to_string())
            .as_deref(),
        Some(sealed.document_id.as_str())
    );
    let pdf_accessibility_file = manifest
        .files
        .iter()
        .find(|file| file.path == pdf_accessibility_path)
        .expect("PDF accessibility evidence report in manifest");
    assert_eq!(pdf_accessibility_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(pdf_accessibility_file.content_type, "application/json");
    assert_eq!(
        pdf_accessibility_file
            .act_id
            .map(|id| id.to_string())
            .as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(
        pdf_accessibility_file
            .document_id
            .map(|id| id.to_string())
            .as_deref(),
        Some(sealed.document_id.as_str())
    );

    let members = zip_members(&first);
    let evidence_index_file = manifest
        .files
        .iter()
        .find(|file| file.path == "evidence/index.json")
        .expect("evidence index in manifest");
    assert_eq!(evidence_index_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(evidence_index_file.content_type, "application/json");
    assert!(evidence_index_file.act_id.is_none());
    assert!(evidence_index_file.document_id.is_none());
    let evidence_index = member_json(&members, "evidence/index.json");
    assert_eq!(evidence_index["index_kind"], "archive_evidence_index");
    assert_eq!(evidence_index["status_scope"], "technical_metadata_only");
    assert_eq!(
        evidence_index["external_validator_reports"]["evidence_kind"],
        "external_validator_report_metadata"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["metadata_schema"],
        "chancela-external-validator-report-evidence/v1"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["indexed_path_prefix"],
        "evidence/external-validators/"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["indexed_path_pattern"],
        "evidence/external-validators/{case_id}-{validator_family}.json"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["raw_report_path_pattern"],
        "evidence/external-validators/{case_id}-{validator_family}-raw-report.{extension}"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["attachment_status"],
        "no_external_validator_report_metadata_attached"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["attachments"],
        json!([])
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["evidence_kind"],
        "pdf_accessibility_report"
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["metadata_schema"],
        "chancela-pdf-accessibility-evidence/v1"
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["indexed_path_prefix"],
        "evidence/pdf-accessibility/"
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["indexed_path_pattern"],
        "evidence/pdf-accessibility/{document_id}.json"
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["attachment_status"],
        "pdf_accessibility_evidence_partially_available"
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["attachments_total"],
        json!(2)
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["attached_count"],
        json!(1)
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["unavailable_count"],
        json!(1)
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["pdf_ua_claimed"],
        true
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["dglab_certification_claimed"],
        false
    );
    assert_eq!(
        evidence_index["pdf_accessibility_reports"]["legal_validity_claimed"],
        false
    );
    let pdf_accessibility_attachments = evidence_index["pdf_accessibility_reports"]["attachments"]
        .as_array()
        .expect("PDF accessibility attachments");
    assert!(
        pdf_accessibility_attachments.iter().any(|entry| {
            entry["document_id"] == sealed.document_id
                && entry["act_id"] == sealed.act_id
                && entry["path"] == pdf_accessibility_path
                && entry["content_type"] == "application/json"
                && entry["evidence_status"] == "pdf_accessibility_report_attached"
                && entry["pdf_ua_claimed"] == true
                && entry["dglab_certification_claimed"] == false
                && entry["legal_validity_claimed"] == false
        }),
        "act PDF accessibility evidence is indexed: {evidence_index}"
    );
    assert!(
        pdf_accessibility_attachments.iter().any(|entry| {
            entry["act_id"].is_null()
                && entry["evidence_status"] == "pdf_accessibility_report_unavailable"
        }),
        "book-level PDF accessibility evidence is explicitly unavailable: {evidence_index}"
    );
    let book_accessibility_path = pdf_accessibility_attachments
        .iter()
        .find(|entry| {
            entry["act_id"].is_null()
                && entry["evidence_status"] == "pdf_accessibility_report_unavailable"
        })
        .and_then(|entry| entry["path"].as_str())
        .expect("book-level PDF accessibility sidecar path");
    let book_accessibility = member_json(&members, book_accessibility_path);
    assert_eq!(
        book_accessibility["evidence_status"],
        "pdf_accessibility_report_unavailable"
    );
    assert_eq!(book_accessibility["pdf_ua_claimed"], false);
    assert_eq!(
        book_accessibility["unavailable_reason"],
        "book_level_document_accessibility_model_unavailable"
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("indexed documents")
            .iter()
            .any(|entry| entry["document_id"] == sealed.document_id
                && entry["signature_evidence_path"] == evidence_path
                && entry["pdf_accessibility_evidence_path"] == pdf_accessibility_path
                && entry["canonical_pdf_path"] == format!("documents/{}.pdf", sealed.document_id)
                && entry["document_metadata_path"]
                    == format!("metadata/{}.json", sealed.document_id)),
        "document evidence paths are indexed: {evidence_index}"
    );
    let evidence_index_text =
        String::from_utf8_lossy(members.get("evidence/index.json").expect("index bytes"));
    assert!(
        !evidence_index_text.contains("trust-list") && !evidence_index_text.contains("trust_list"),
        "evidence index stays local technical metadata scoped: {evidence_index}"
    );
    assert!(
        !evidence_index_text.contains("pdfuaid")
            && !evidence_index_text.contains("DGLAB")
            && !evidence_index_text.contains("\"dglab_certification_claimed\":true")
            && !evidence_index_text.contains("\"legal_validity_claimed\":true"),
        "evidence index must not carry DGLAB or legal-validity claims: {evidence_index}"
    );

    let accessibility = member_json(&members, &pdf_accessibility_path);
    assert_eq!(accessibility["evidence_kind"], "pdf_accessibility_report");
    assert_eq!(
        accessibility["evidence_status"],
        "pdf_accessibility_report_attached"
    );
    assert_eq!(accessibility["pdf_ua_claimed"], true);
    assert_eq!(accessibility["dglab_certification_claimed"], false);
    assert_eq!(accessibility["legal_validity_claimed"], false);
    assert_eq!(accessibility["report_version"], json!(12));
    assert_eq!(
        accessibility["accessibility_report_json"]["version"],
        json!(12)
    );
    let blocker_delta = &accessibility["accessibility_report_json"]["pdf_ua_blocker_delta"];
    assert_eq!(
        blocker_delta["delta_basis"],
        "local_chancela_doc_writer_evidence_only"
    );
    assert_eq!(blocker_delta["pdf_ua_claimed"], true);
    assert_eq!(blocker_delta["cleared_count"], json!(13));
    assert_eq!(blocker_delta["remaining_count"], json!(0));
    assert_eq!(blocker_delta["remaining_blockers"], json!([]));
    assert!(
        blocker_delta["cleared_blockers"]
            .as_array()
            .expect("cleared PDF/UA blockers")
            .contains(&json!("no_alt_text_model")),
        "PDF/UA blocker delta is embedded: {accessibility}"
    );
    let table_semantics = &accessibility["accessibility_report_json"]["tagged_structure"]["tables"];
    assert_eq!(table_semantics["header_cells_have_scope"], true);
    assert_eq!(table_semantics["table_rows_missing_header_count"], json!(0));
    assert_eq!(table_semantics["row_header_cells_have_scope_row"], true);
    assert_eq!(
        table_semantics["column_header_cells_have_scope_column"],
        true
    );
    assert_eq!(
        accessibility["accessibility_report_json"]["pdf_ua_claimed"],
        true
    );
    assert_eq!(
        accessibility["pdf_ua_blockers"]
            .as_array()
            .expect("PDF/UA blockers"),
        &Vec::<Value>::new(),
        "conforming document has no remaining PDF/UA blockers: {accessibility}"
    );
    let accessibility_text =
        String::from_utf8_lossy(members.get(&pdf_accessibility_path).expect("sidecar bytes"));
    assert!(
        !accessibility_text.contains("pdfuaid")
            && !accessibility_text.contains("DGLAB")
            && !accessibility_text.contains("\"dglab_certification_claimed\":true")
            && !accessibility_text.contains("\"legal_validity_claimed\":true"),
        "PDF accessibility sidecar never carries DGLAB or legal-validity claims: {accessibility}"
    );

    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "not_signed");
    assert_eq!(report["source"], "documents");
    assert_eq!(report["archive_export_revalidated"], false);
    assert_eq!(
        report["reason"],
        "no stored signature metadata matched this act document at export time"
    );
    assert!(
        report.get("signature").is_none(),
        "unsigned report must not claim signature evidence: {report}"
    );
    assert!(
        !String::from_utf8_lossy(members.get(&evidence_path).expect("evidence bytes"))
            .contains("placeholder"),
        "report must not contain placeholder evidence"
    );
}

#[tokio::test]
async fn archive_package_reports_book_only_pdf_accessibility_evidence_unavailable() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let book_id = open_empty_archive_book(&state, &token).await;
    close_book(&state, &token, &book_id).await;

    let package = archive_package_bytes(&state, &book_id, &token).await;
    let manifest = validate_package(&package).expect("archive package validates");
    assert!(
        manifest
            .document_ids
            .iter()
            .all(|document_id| Uuid::parse_str(&book_id).expect("book uuid") != *document_id),
        "book-level document ids are distinct preserved document ids"
    );

    let members = zip_members(&package);
    let evidence_index = member_json(&members, "evidence/index.json");
    let indexed_docs = evidence_index["documents"]
        .as_array()
        .expect("indexed documents");
    assert!(
        !indexed_docs.is_empty(),
        "book-only archive has preserved book documents: {evidence_index}"
    );
    assert!(
        indexed_docs.iter().all(|entry| entry["act_id"].is_null()),
        "book-only archive must not index act-level documents: {evidence_index}"
    );

    let reports = &evidence_index["pdf_accessibility_reports"];
    let attachments = reports["attachments"]
        .as_array()
        .expect("PDF accessibility attachments");
    assert_eq!(
        reports["attachment_status"],
        "pdf_accessibility_evidence_unavailable"
    );
    assert_eq!(reports["attachments_total"], json!(attachments.len()));
    assert_eq!(reports["attached_count"], json!(0));
    assert_eq!(reports["unavailable_count"], json!(attachments.len()));
    assert_eq!(reports["pdf_ua_claimed"], false);
    assert!(
        !attachments.is_empty(),
        "book-only archive must report unavailable book-level accessibility evidence: {reports}"
    );
    assert!(
        attachments.iter().all(|entry| {
            entry["act_id"].is_null()
                && entry["evidence_status"] == "pdf_accessibility_report_unavailable"
                && entry["pdf_ua_claimed"] == false
                && entry["dglab_certification_claimed"] == false
                && entry["legal_validity_claimed"] == false
        }),
        "all book-only accessibility entries are fail-closed unavailable evidence: {reports}"
    );

    for attachment in attachments {
        let path = attachment["path"]
            .as_str()
            .expect("PDF accessibility sidecar path");
        let sidecar = member_json(&members, path);
        assert_eq!(
            sidecar["evidence_status"],
            "pdf_accessibility_report_unavailable"
        );
        assert_eq!(
            sidecar["unavailable_reason"],
            "book_level_document_accessibility_model_unavailable"
        );
        assert_eq!(sidecar["pdf_ua_claimed"], false);
        assert_eq!(sidecar["dglab_certification_claimed"], false);
        assert_eq!(sidecar["legal_validity_claimed"], false);
    }
}

#[tokio::test]
async fn local_dglab_interchange_manifest_requires_book_export_permission() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let owner_token = bootstrap(&state).await;
    let sealed = seal_act(&state, &owner_token).await;
    let reader_token = reader_token_without_book_export(&state, &owner_token).await;
    let uri = local_dglab_interchange_manifest_uri(&sealed.book_id);

    let (status, body) = send(&state, get_req(&uri, &reader_token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "reader denied: {body}");

    let (status, body) = send(&state, get_req(&uri, &owner_token)).await;
    assert_eq!(status, StatusCode::OK, "owner allowed: {body}");
    assert_eq!(
        body["schema"],
        "chancela-local-dglab-interchange-manifest/v1"
    );
}

#[tokio::test]
async fn local_dglab_interchange_manifest_is_deterministic_read_only_and_not_packaged() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;

    let before_ledger = ledger_events(&state, &token).await;
    let before_paths = data_dir_paths(&dir.0);
    let first = local_dglab_interchange_manifest_bytes(&state, &sealed.book_id, &token).await;
    let second = local_dglab_interchange_manifest_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(first, second, "local DGLAB manifest JSON is deterministic");

    let after_ledger = ledger_events(&state, &token).await;
    let after_paths = data_dir_paths(&dir.0);
    assert_eq!(
        before_ledger, after_ledger,
        "local DGLAB manifest endpoint must not append ledger events"
    );
    assert_eq!(
        before_paths, after_paths,
        "local DGLAB manifest endpoint must not create persisted package or manifest files"
    );
    assert!(
        !data_dir_contains_subslice(&dir.0, &first),
        "local DGLAB manifest endpoint must not persist returned manifest bytes"
    );

    let manifest: Value = serde_json::from_slice(&first).expect("local DGLAB manifest JSON");
    assert_eq!(
        manifest["schema"],
        "chancela-local-dglab-interchange-manifest/v1"
    );
    assert_eq!(
        manifest["profile"],
        "chancela-local-dglab-interchange-manifest/v1"
    );
    assert_eq!(manifest["source_manifest_path"], "manifest.json");
    assert_eq!(manifest["evidence_index_path"], "evidence/index.json");
    for flag in [
        "official_dglab_interchange",
        "dglab_certification_claimed",
        "external_dglab_approval_obtained",
        "legal_archive_certified",
        "destructive_disposal_performed",
    ] {
        assert_eq!(manifest[flag], false, "{flag} must remain false");
    }
    assert_eq!(manifest["retention"]["legal_hold"], false);

    let files = manifest["files"].as_array().expect("manifest files");
    assert!(
        files
            .iter()
            .any(|file| file["path"] == "evidence/index.json"),
        "source evidence index is declared in local DGLAB manifest: {manifest}"
    );
    assert_eq!(
        manifest["file_fixity_summary"]["file_count"],
        json!(files.len())
    );
    let total_byte_len: u64 = files
        .iter()
        .map(|file| file["byte_len"].as_u64().expect("file byte_len"))
        .sum();
    assert_eq!(
        manifest["file_fixity_summary"]["total_byte_len"],
        json!(total_byte_len)
    );

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert!(
        !data_dir_contains_subslice(&dir.0, &package),
        "local DGLAB manifest endpoint must not persist source package bytes"
    );
    let members = zip_members(&package);
    assert!(
        members.keys().all(|path| {
            !path.contains("local-dglab")
                && !path.contains("local_dglab")
                && !path.contains("dglab-interchange")
        }),
        "local DGLAB manifest must not be a ZIP member: {:?}",
        members.keys().collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn archive_package_indexes_generated_absent_owner_dispatch_evidence_metadata_only() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_condominium_absent_owner_act(&state, &token).await;
    let note = "unique archive preservation note 2026-07-12T12:35:12Z idempotency sentinel";
    let evidence = record_absent_owner_dispatch_evidence(
        &state,
        &token,
        &sealed.communication_document_id,
        note,
    )
    .await;
    assert_eq!(
        evidence["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    let idempotency_key = evidence["evidence"]["idempotency_key"]
        .as_str()
        .expect("dispatch evidence idempotency key");

    let before_ledger = ledger_events(&state, &token).await;
    let first = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let second = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(
        first, second,
        "generated-dispatch evidence packaging remains deterministic"
    );
    let after_ledger = ledger_events(&state, &token).await;
    assert_eq!(
        before_ledger, after_ledger,
        "archive package export must read dispatch evidence without appending events"
    );

    let manifest = validate_package(&first).expect("archive package validates");
    assert!(
        manifest
            .document_ids
            .iter()
            .any(|id| id.to_string() == sealed.ata_document_id),
        "canonical Ata document id remains in manifest.document_ids"
    );
    assert!(
        manifest
            .document_ids
            .iter()
            .all(|id| id.to_string() != sealed.communication_document_id),
        "generated communication metadata sidecar must not promote its id into manifest.document_ids"
    );
    let sidecar_path = format!(
        "evidence/generated-dispatch/{}.json",
        sealed.communication_document_id
    );
    let sidecar_file = manifest
        .files
        .iter()
        .find(|file| file.path == sidecar_path)
        .expect("generated dispatch sidecar in manifest");
    assert_eq!(sidecar_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(sidecar_file.content_type, "application/json");
    assert_eq!(
        sidecar_file.act_id.map(|id| id.to_string()).as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(sidecar_file.document_id, None);

    let members = zip_members(&first);
    assert!(
        !members.contains_key(&format!(
            "documents/{}.pdf",
            sealed.communication_document_id
        )),
        "generated communication proof/PDF bytes are not added by this metadata-only slice"
    );
    let sidecar = member_json(&members, &sidecar_path);
    assert_eq!(
        sidecar["evidence_kind"],
        "generated_document_dispatch_evidence_metadata"
    );
    assert_eq!(
        sidecar["metadata_schema"],
        "chancela-generated-document-dispatch-evidence-metadata/v1"
    );
    assert_eq!(sidecar["status_scope"], "technical_metadata_only");
    assert_eq!(
        sidecar["generated_document_id"],
        sealed.communication_document_id
    );
    assert_eq!(sidecar["act_id"], sealed.act_id);
    assert_eq!(sidecar["template_id"], "condominio-comunicacao-ausentes/v1");
    assert_eq!(
        sidecar["generated_document_download"],
        format!(
            "/v1/documents/generated/{}",
            sealed.communication_document_id
        )
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["dispatch_completed"],
        false
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["completion_basis"],
        "none"
    );
    assert_eq!(
        sidecar["coverage"]["required_recipients"],
        json!(["Fração B"])
    );
    assert_eq!(
        sidecar["coverage"]["recorded_recipients"],
        json!(["Fração B"])
    );
    assert_eq!(sidecar["coverage"]["missing_recipients"], json!([]));
    assert_eq!(sidecar["coverage"]["all_required_recipients_covered"], true);
    for flag in [
        "sending_performed_by_chancela",
        "delivery_confirmed",
        "dispatch_completed",
        "legal_notice_completion_claimed",
        "legal_sufficiency_claimed",
        "provider_execution_claimed",
        "registry_filing_claimed",
        "bundle_readiness_claimed",
        "dglab_certification_claimed",
        "legal_archive_acceptance_claimed",
        "proof_bytes_included",
        "operator_note_included",
    ] {
        assert_eq!(sidecar[flag], false, "{flag} must remain false");
    }

    let record = &sidecar["records"].as_array().expect("records")[0];
    assert_eq!(record["dispatched_at"], "2026-04-01T10:00:00Z");
    assert!(
        record["recorded_at"]
            .as_str()
            .is_some_and(|ts| !ts.is_empty())
    );
    assert_eq!(record["channel"], "RegisteredLetter");
    assert_eq!(record["reference"], "RR123456789PT");
    assert_eq!(record["evidence_reference"], "archive:dispatch-proof-1");
    assert_eq!(record["imported_document_id"], Value::Null);
    assert_eq!(record["recipients"], json!(["Fração B"]));
    assert_eq!(record["dispatch_completed"], false);
    assert_eq!(record["completion_basis"], "none");
    assert_eq!(record["bytes_included"], false);
    assert_eq!(record["operator_note_included"], false);
    assert!(
        record.get("idempotency_key").is_none(),
        "note-derived idempotency key must stay out of archive sidecar records: {record}"
    );

    let evidence_index = member_json(&members, "evidence/index.json");
    let generated_dispatch = &evidence_index["generated_dispatch_evidence"];
    assert_eq!(
        generated_dispatch["evidence_kind"],
        "generated_document_dispatch_evidence_metadata"
    );
    assert_eq!(
        generated_dispatch["metadata_schema"],
        "chancela-generated-document-dispatch-evidence-metadata/v1"
    );
    assert_eq!(
        generated_dispatch["indexed_path_prefix"],
        "evidence/generated-dispatch/"
    );
    assert_eq!(
        generated_dispatch["indexed_path_pattern"],
        "evidence/generated-dispatch/{document_id}.json"
    );
    assert_eq!(
        generated_dispatch["attachment_status"],
        "generated_dispatch_evidence_metadata_attached"
    );
    assert_eq!(
        generated_dispatch["attachments"],
        json!([{
            "generated_document_id": sealed.communication_document_id.clone(),
            "act_id": sealed.act_id.clone(),
            "template_id": "condominio-comunicacao-ausentes/v1",
            "path": sidecar_path.clone(),
            "content_type": "application/json",
            "generated_document_download": format!(
                "/v1/documents/generated/{}",
                sealed.communication_document_id
            ),
            "dispatch_evidence_status": {
                "status": "operator_evidence_covered",
                "required": true,
                "evidence_attached": true,
                "dispatch_completed": false,
                "completion_basis": "none",
                "required_recipients": ["Fração B"],
                "recorded_recipients": ["Fração B"],
                "missing_recipients": [],
                "note": "operator-recorded dispatch evidence covers all absent recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
            },
            "proof_bytes_included": false,
            "operator_note_included": false
        }])
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical document entries")
            .iter()
            .any(|entry| entry["document_id"] == sealed.ata_document_id),
        "canonical Ata remains the package document: {evidence_index}"
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical document entries")
            .iter()
            .all(|entry| entry["document_id"] != sealed.communication_document_id),
        "generated communication is referenced as dispatch metadata, not canonical PDF: {evidence_index}"
    );

    let sidecar_text = String::from_utf8_lossy(members.get(&sidecar_path).expect("sidecar bytes"));
    let index_text = String::from_utf8_lossy(members.get("evidence/index.json").expect("index"));
    assert!(
        !sidecar_text.contains(note)
            && !sidecar_text.contains("\"operator_note\":")
            && !index_text.contains(note)
            && !index_text.contains("\"operator_note\":"),
        "free-form operator notes are excluded from preservation output"
    );
    assert!(
        !sidecar_text.contains(idempotency_key)
            && !sidecar_text.contains("\"idempotency_key\":")
            && !sidecar_text.contains("\"fingerprint\":")
            && !index_text.contains(idempotency_key)
            && !index_text.contains("\"idempotency_key\":")
            && !index_text.contains("\"fingerprint\":"),
        "note-derived stable identifiers are excluded from preservation output"
    );
}

#[tokio::test]
async fn archive_package_indexes_generated_convening_notice_dispatch_evidence_metadata_only() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_generated_convening_notice_act(&state, &token).await;
    let note = "unique generated convening archive note 2026-07-15T09:00:00Z sentinel";
    let evidence = record_generated_convening_notice_dispatch_evidence(
        &state,
        &token,
        &sealed.notice_document_id,
        note,
    )
    .await;
    assert_eq!(
        evidence["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    let idempotency_key = evidence["evidence"]["idempotency_key"]
        .as_str()
        .expect("dispatch evidence idempotency key");

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&package).expect("archive package validates");
    assert!(
        manifest
            .document_ids
            .iter()
            .any(|id| id.to_string() == sealed.ata_document_id),
        "canonical Ata document id remains in manifest.document_ids"
    );
    assert!(
        manifest
            .document_ids
            .iter()
            .all(|id| id.to_string() != sealed.notice_document_id),
        "generated convening notice metadata sidecar must not promote its id into manifest.document_ids"
    );

    let sidecar_path = format!(
        "evidence/generated-dispatch/{}.json",
        sealed.notice_document_id
    );
    let sidecar_file = manifest
        .files
        .iter()
        .find(|file| file.path == sidecar_path)
        .expect("generated convening dispatch sidecar in manifest");
    assert_eq!(sidecar_file.role, PackageFileRole::EvidenceReport);
    assert_eq!(sidecar_file.content_type, "application/json");
    assert_eq!(
        sidecar_file.act_id.map(|id| id.to_string()).as_deref(),
        Some(sealed.act_id.as_str())
    );
    assert_eq!(sidecar_file.document_id, None);

    let members = zip_members(&package);
    assert!(
        !members.contains_key(&format!("documents/{}.pdf", sealed.notice_document_id)),
        "generated convening notice PDF bytes are not added by this metadata-only slice"
    );
    let sidecar = member_json(&members, &sidecar_path);
    assert_eq!(
        sidecar["evidence_kind"],
        "generated_document_dispatch_evidence_metadata"
    );
    assert_eq!(
        sidecar["metadata_schema"],
        "chancela-generated-document-dispatch-evidence-metadata/v1"
    );
    assert_eq!(sidecar["status_scope"], "technical_metadata_only");
    assert_eq!(sidecar["generated_document_id"], sealed.notice_document_id);
    assert_eq!(sidecar["act_id"], sealed.act_id);
    assert_eq!(sidecar["template_id"], "csc-convocatoria-ag/v1");
    assert_eq!(
        sidecar["dispatch_evidence_status"]["status"],
        "operator_evidence_covered"
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["dispatch_completed"],
        false
    );
    assert_eq!(
        sidecar["dispatch_evidence_status"]["completion_basis"],
        "none"
    );
    assert_eq!(
        sidecar["coverage"]["required_recipients"],
        json!(["Ana Sócia", "Bruno Sócio"])
    );
    assert_eq!(
        sidecar["coverage"]["recorded_recipients"],
        json!(["Ana Sócia", "Bruno Sócio"])
    );
    assert_eq!(sidecar["coverage"]["missing_recipients"], json!([]));
    assert_eq!(sidecar["coverage"]["all_required_recipients_covered"], true);
    for flag in [
        "sending_performed_by_chancela",
        "delivery_confirmed",
        "dispatch_completed",
        "legal_notice_completion_claimed",
        "legal_sufficiency_claimed",
        "provider_execution_claimed",
        "registry_filing_claimed",
        "bundle_readiness_claimed",
        "dglab_certification_claimed",
        "legal_archive_acceptance_claimed",
        "proof_bytes_included",
        "operator_note_included",
    ] {
        assert_eq!(sidecar[flag], false, "{flag} must remain false");
    }

    let record = &sidecar["records"].as_array().expect("records")[0];
    assert_eq!(record["dispatched_at"], "2026-03-01T09:00:00Z");
    assert_eq!(record["channel"], "Email");
    assert_eq!(record["reference"], "MSG-1");
    assert_eq!(
        record["evidence_reference"],
        "archive:generated-convening-notice-dispatch"
    );
    assert_eq!(record["recipients"], json!(["Ana Sócia", "Bruno Sócio"]));
    assert_eq!(record["dispatch_completed"], false);
    assert_eq!(record["completion_basis"], "none");
    assert_eq!(record["bytes_included"], false);
    assert_eq!(record["operator_note_included"], false);

    let evidence_index = member_json(&members, "evidence/index.json");
    let generated_dispatch = &evidence_index["generated_dispatch_evidence"];
    assert_eq!(
        generated_dispatch["attachment_status"],
        "generated_dispatch_evidence_metadata_attached"
    );
    assert_eq!(
        generated_dispatch["attachments"],
        json!([{
            "generated_document_id": sealed.notice_document_id.clone(),
            "act_id": sealed.act_id.clone(),
            "template_id": "csc-convocatoria-ag/v1",
            "path": sidecar_path.clone(),
            "content_type": "application/json",
            "generated_document_download": format!(
                "/v1/documents/generated/{}",
                sealed.notice_document_id
            ),
            "dispatch_evidence_status": {
                "status": "operator_evidence_covered",
                "required": true,
                "evidence_attached": true,
                "dispatch_completed": false,
                "completion_basis": "none",
                "required_recipients": ["Ana Sócia", "Bruno Sócio"],
                "recorded_recipients": ["Ana Sócia", "Bruno Sócio"],
                "missing_recipients": [],
                "note": "operator-recorded dispatch evidence covers all generated convening notice recipients, but no sending, delivery, legal notice completion, or legal sufficiency is claimed"
            },
            "proof_bytes_included": false,
            "operator_note_included": false
        }])
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical document entries")
            .iter()
            .any(|entry| entry["document_id"] == sealed.ata_document_id),
        "canonical Ata remains the package document: {evidence_index}"
    );
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("canonical document entries")
            .iter()
            .all(|entry| entry["document_id"] != sealed.notice_document_id),
        "generated convening notice is referenced as dispatch metadata, not canonical PDF: {evidence_index}"
    );

    let sidecar_text = String::from_utf8_lossy(members.get(&sidecar_path).expect("sidecar bytes"));
    let index_text = String::from_utf8_lossy(members.get("evidence/index.json").expect("index"));
    assert!(
        !sidecar_text.contains(note)
            && !sidecar_text.contains("\"operator_note\":")
            && !index_text.contains(note)
            && !index_text.contains("\"operator_note\":"),
        "free-form operator notes are excluded from preservation output"
    );
    assert!(
        !sidecar_text.contains(idempotency_key)
            && !sidecar_text.contains("\"idempotency_key\":")
            && !sidecar_text.contains("\"fingerprint\":")
            && !index_text.contains(idempotency_key)
            && !index_text.contains("\"idempotency_key\":")
            && !index_text.contains("\"fingerprint\":"),
        "note-derived stable identifiers are excluded from preservation output"
    );
}

#[tokio::test]
async fn archive_package_indexes_matching_external_validator_metadata_only() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    let document_sha256 = sha256_hex(&document.pdf_bytes);
    let valid = external_validator_metadata_bytes("runtime-valid", "eu-dss", &document_sha256);
    let valid_sha256 = sha256_hex(&valid);

    let mut legal_claim =
        external_validator_metadata_value("runtime-legal", "adobe", &document_sha256);
    legal_claim["legal_validity_claimed"] = json!(true);
    let mut traversal =
        external_validator_metadata_value("runtime-traversal", "eu-dss", &document_sha256);
    traversal["archive_attachment"]["suggested_path"] =
        json!("evidence/external-validators/../runtime-traversal-eu-dss.json");
    let duplicate_a =
        external_validator_metadata_bytes("runtime-duplicate", "eu-dss", &document_sha256);
    let duplicate_b =
        external_validator_metadata_bytes("runtime-duplicate", "eu-dss", &document_sha256);
    let mut malformed_sha =
        external_validator_metadata_value("runtime-bad-sha", "eu-dss", &document_sha256);
    malformed_sha["document"]["sha256"] = json!("not-a-sha256");

    {
        let mut metadata = state.external_validator_report_metadata.write().await;
        metadata.push(b"not json".to_vec());
        metadata.push(legal_claim.to_string().into_bytes());
        metadata.push(traversal.to_string().into_bytes());
        metadata.push(duplicate_a);
        metadata.push(duplicate_b);
        metadata.push(malformed_sha.to_string().into_bytes());
        metadata.push(valid.clone());
    }

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    validate_package(&package).expect("archive package validates");
    let members = zip_members(&package);
    let evidence_path = "evidence/external-validators/runtime-valid-eu-dss.json";
    assert_eq!(
        members
            .get(evidence_path)
            .expect("validator metadata member"),
        &valid
    );
    assert!(
        !members.contains_key("evidence/external-validators/runtime-duplicate-eu-dss.json"),
        "duplicate suggested paths are ignored"
    );
    assert!(
        !members.contains_key("evidence/external-validators/runtime-valid-eu-dss-raw-report.json"),
        "manifest-only raw validator report bytes are not packaged"
    );
    assert!(
        members.keys().all(|path| !path.contains("runtime-legal")
            && !path.contains("runtime-traversal")
            && !path.contains("runtime-bad-sha")),
        "invalid metadata is not packaged: {:?}",
        members.keys().collect::<Vec<_>>()
    );

    let evidence_index = member_json(&members, "evidence/index.json");
    assert_eq!(
        evidence_index["external_validator_reports"]["attachment_status"],
        "external_validator_report_metadata_attached"
    );
    assert_eq!(
        evidence_index["external_validator_reports"]["attachments"],
        json!([{
            "case_id": "runtime-valid",
            "validator_family": "eu-dss",
            "path": evidence_path,
            "content_type": "application/json",
            "sha256": valid_sha256,
            "raw_report": {
                "preservation_status": "raw_report_manifest_only",
                "content_type": "application/json",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "size_bytes": 2,
                "source_filename": "eu-dss.json"
            }
        }])
    );
    assert!(
        !String::from_utf8_lossy(members.get("evidence/index.json").expect("index bytes"))
            .contains("trust-list"),
        "evidence index stays technical metadata scoped"
    );
    let attachment = member_json(&members, evidence_path);
    assert_eq!(attachment["legal_validity_claimed"], false);
    assert_eq!(
        attachment["evidence_scope"]["legal_validity_assessment"],
        "not_assessed"
    );
    assert!(
        attachment["observed"].is_null(),
        "raw external validator reports are not packaged as structured findings"
    );
}

#[tokio::test]
async fn archive_package_embeds_matching_external_validator_raw_report_attachment() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let document = stored_document(&state, parse_act_id(&sealed.act_id), &sealed.document_id);
    let document_sha256 = sha256_hex(&document.pdf_bytes);
    let (metadata, raw_report, raw_report_sha256) =
        external_validator_metadata_with_raw_report_bytes(
            "runtime-raw",
            "eu-dss",
            &document_sha256,
        );
    let metadata_sha256 = sha256_hex(&metadata);

    state
        .external_validator_report_metadata
        .write()
        .await
        .push(metadata.clone());

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&package).expect("archive package validates");
    let members = zip_members(&package);
    let metadata_path = "evidence/external-validators/runtime-raw-eu-dss.json";
    let raw_report_path = "evidence/external-validators/runtime-raw-eu-dss-raw-report.json";
    assert_eq!(
        members
            .get(metadata_path)
            .expect("validator metadata member"),
        &metadata
    );
    assert_eq!(
        members
            .get(raw_report_path)
            .expect("validator raw report member"),
        &raw_report
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == raw_report_path
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "raw report is declared as technical evidence: {manifest:?}"
    );

    let evidence_index = member_json(&members, "evidence/index.json");
    assert_eq!(
        evidence_index["external_validator_reports"]["attachments"],
        json!([{
            "case_id": "runtime-raw",
            "validator_family": "eu-dss",
            "path": metadata_path,
            "content_type": "application/json",
            "sha256": metadata_sha256,
            "raw_report": {
                "preservation_status": "raw_report_attached",
                "path": raw_report_path,
                "suggested_path": raw_report_path,
                "content_type": "application/json",
                "sha256": raw_report_sha256,
                "size_bytes": raw_report.len(),
                "source_filename": "eu-dss-raw.json"
            }
        }])
    );
    assert!(
        !String::from_utf8_lossy(members.get("evidence/index.json").expect("index bytes"))
            .contains("\"legal_validity_claimed\":true"),
        "raw external validator report evidence stays technical and no-claim scoped"
    );
    let raw_text = String::from_utf8_lossy(
        members
            .get(raw_report_path)
            .expect("validator raw report member"),
    );
    assert!(
        !raw_text.contains("validity") && !raw_text.contains("qualified"),
        "fixture raw report member carries no legal-validity claim"
    );
}

#[tokio::test]
async fn archive_package_reports_persisted_signature_metadata_as_evidence() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = ActId(Uuid::parse_str(&sealed.act_id).expect("act uuid"));

    let signed_pdf_bytes = b"%PDF-1.7\n%signed fixture\n".to_vec();
    let signer_cert_der = b"fixture signer certificate DER".to_vec();
    let timestamp_token_der = b"fixture timestamp token DER".to_vec();
    let signed_pdf_digest = sha256_hex(&signed_pdf_bytes);
    let signer_cert_digest = sha256_hex(&signer_cert_der);
    let timestamp_token_digest = sha256_hex(&timestamp_token_der);
    let timestamp_trust_report_json = r#"{"decision":"rejected","policy_oid":"1.2.3.4","policy_oid_accepted":false,"tsa_certificate_embedded":true,"embedded_certificate_count":2,"qtst_status":"unknown","qtst_authenticated":true,"qtst_matches":[{"provider_name":"Provider","service_name":"QTST","granted_and_effective":false,"trust_anchor_count":1}],"trust_anchor_count":1,"certificate_path_valid":false,"certificate_path_anchor_index":null,"certificate_path_len":null,"failure_reasons":["fixture diagnostic"],"status_scope":"technical_evidence_only"}"#;
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Amelia Marques".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:01:00 UTC),
        signer_cert_der: signer_cert_der.clone(),
        timestamp_token_der: Some(timestamp_token_der.clone()),
        timestamp_trust_report_json: Some(timestamp_trust_report_json.to_owned()),
        signer_capacity_evidence_json: None,
        signed_pdf_bytes: signed_pdf_bytes.clone(),
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let first = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let second = archive_package_bytes(&state, &sealed.book_id, &token).await;
    assert_eq!(first, second, "signed archive output stays deterministic");

    let manifest = validate_package(&first).expect("archive package validates");
    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("signed/{}.pdf", sealed.document_id)
                && file.role == PackageFileRole::Other
                && file.content_type == "application/pdf; profile=PAdES-B-T"
        }),
        "signed PDF sidecar has timestamp-aware profile: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| {
            file.path == evidence_path
                && file.role == PackageFileRole::EvidenceReport
                && file.content_type == "application/json"
        }),
        "signature evidence JSON is declared: {manifest:?}"
    );
    assert!(
        manifest.files.iter().any(|file| file.path
            == format!("signing/{}.json", sealed.document_id)
            && file.role == PackageFileRole::SigningReport),
        "signing metadata sidecar remains declared: {manifest:?}"
    );

    let members = zip_members(&first);
    assert_eq!(
        members
            .get(&format!("signed/{}.pdf", sealed.document_id))
            .expect("signed PDF member"),
        &signed_pdf_bytes
    );
    assert_eq!(
        members
            .get(&format!("evidence/{}-signer-cert.der", sealed.document_id))
            .expect("signer cert member"),
        &signer_cert_der
    );
    assert_eq!(
        members
            .get(&format!(
                "evidence/{}-timestamp-token.tsr",
                sealed.document_id
            ))
            .expect("timestamp member"),
        &timestamp_token_der
    );
    let evidence_index = member_json(&members, "evidence/index.json");
    assert!(
        evidence_index["documents"]
            .as_array()
            .expect("indexed documents")
            .iter()
            .any(|entry| entry["document_id"] == sealed.document_id
                && entry["signed_pdf_path"] == format!("signed/{}.pdf", sealed.document_id)
                && entry["signing_metadata_path"]
                    == format!("signing/{}.json", sealed.document_id)
                && entry["signer_certificate_path"]
                    == format!("evidence/{}-signer-cert.der", sealed.document_id)
                && entry["timestamp_token_path"]
                    == format!("evidence/{}-timestamp-token.tsr", sealed.document_id)),
        "signed evidence paths are indexed: {evidence_index}"
    );

    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "signed");
    assert_eq!(report["source"], "signed_documents");
    assert_eq!(report["archive_export_revalidated"], false);
    assert!(
        report.get("reason").is_none(),
        "signed report has no absence reason"
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["path"],
        format!("signed/{}.pdf", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["content_type"],
        "application/pdf; profile=PAdES-B-T"
    );
    assert_eq!(
        report["signature"]["signed_pdf"]["sha256"],
        signed_pdf_digest
    );
    assert_eq!(
        report["signature"]["signature"]["family"],
        "CartaoDeCidadao"
    );
    assert_eq!(
        report["signature"]["signature"]["evidentiary_level"],
        "Qualified"
    );
    assert_eq!(
        report["signature"]["signature"]["trusted_list_status"],
        "Granted"
    );
    assert_eq!(
        report["signature"]["signature"]["signing_time"],
        "2026-04-01T12:00:00Z"
    );
    assert_eq!(
        report["signature"]["signature"]["signed_at"],
        "2026-04-01T12:01:00Z"
    );
    assert_eq!(
        report["signature"]["signer_certificate"]["path"],
        format!("evidence/{}-signer-cert.der", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["signer_certificate"]["sha256"],
        signer_cert_digest
    );
    assert_eq!(report["signature"]["timestamp_token"]["present"], true);
    assert_eq!(
        report["signature"]["timestamp_token"]["path"],
        format!("evidence/{}-timestamp-token.tsr", sealed.document_id)
    );
    assert_eq!(
        report["signature"]["timestamp_token"]["sha256"],
        timestamp_token_digest
    );
    assert_eq!(
        report["signature"]["timestamp_trust"]["decision"],
        "rejected"
    );
    assert_eq!(
        report["signature"]["timestamp_trust"]["policy_oid"],
        "1.2.3.4"
    );
    assert_eq!(
        report["signature"]["timestamp_trust"]["qtst_matches"][0]["service_name"],
        "QTST"
    );
    assert_eq!(
        report["signature"]["timestamp_trust"]["status_scope"],
        "technical_evidence_only"
    );
    let doc_timestamp = &report["signature"]["doc_timestamp"];
    assert_eq!(
        doc_timestamp["basis"],
        "embedded_pdf_doctimestamp_inspection_only"
    );
    assert_eq!(doc_timestamp["present"], false);
    assert_eq!(doc_timestamp["count"], 0);
    assert_eq!(doc_timestamp["token_sha256"], json!([]));
    assert_eq!(doc_timestamp["validations"], json!([]));
    assert_eq!(doc_timestamp["all_imprints_valid"], false);
    assert_eq!(doc_timestamp["inspection_status"], "inspection_unavailable");
    assert_eq!(
        report["signature"]["renewal_policy"]["status"],
        "not_configured"
    );
    assert_eq!(
        report["signature"]["renewal_policy"]["action"],
        "manual_review"
    );
    assert_eq!(report["signature"]["legal_b_lta_claimed"], false);
    assert_eq!(
        report["signature"]["persisted_validation"]["byte_range_covers_whole_file_except_contents"],
        "validated_before_persistence"
    );
    assert_eq!(
        report["signature"]["persisted_validation"]["timestamp_trust"],
        "persisted_technical_timestamp_trust_report"
    );
    assert_eq!(
        report["signature"]["persisted_validation"]["cryptographic_revalidation_at_export"],
        "not_performed"
    );
    assert_ne!(
        report["signature"]["persisted_validation"]["timestamp_trust"],
        "not_persisted_full_validator_inputs"
    );
    assert!(
        !String::from_utf8_lossy(members.get(&evidence_path).expect("evidence bytes"))
            .contains("placeholder"),
        "report must not contain placeholder evidence"
    );
}

#[tokio::test]
async fn archive_package_reports_embedded_dss_without_legal_b_lt_claim() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = ActId(Uuid::parse_str(&sealed.act_id).expect("act uuid"));
    let unsigned = state
        .store
        .as_ref()
        .expect("store")
        .document_for_act(act_id)
        .expect("document lookup")
        .expect("sealed document");

    let provider = MockProvider::deterministic_rsa(SigningFamily::CartaoDeCidadao);
    let signer_cert_der = provider
        .signing_certificate_der()
        .expect("signer certificate");
    let signing_time = datetime!(2026-04-01 12:00:00 UTC);
    let signed_pdf = sign_pdf_pades(
        &provider,
        &unsigned.pdf_bytes,
        signing_time,
        &SignOptions::default(),
    )
    .expect("PAdES signing");
    let tsa = MockTsaServer::granted();
    let tsa_url = tsa.url().to_owned();
    let (timestamped_pdf, timestamp_token_der) = tokio::task::spawn_blocking(move || {
        timestamp_pdf_with_url(&signed_pdf, &tsa_url).expect("timestamped PDF")
    })
    .await
    .expect("timestamp task");
    let dss_evidence = DssEvidence {
        certificates: vec![signer_cert_der.clone()],
        ocsp_responses: vec![OCSP_DER_FIXTURE.to_vec()],
        crls: vec![CRL_DER_FIXTURE.to_vec()],
    };
    let (signed_pdf_with_dss, dss_report) =
        attach_pdf_dss(&timestamped_pdf, &dss_evidence).expect("DSS append");
    assert!(dss_report.present);
    assert_eq!(dss_report.vri_count, 1);
    assert_eq!(dss_report.ocsp_count(), 1);
    assert_eq!(dss_report.crl_count(), 1);

    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest: sha256_hex(&signed_pdf_with_dss),
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Chancela mock signer".to_owned()),
        signing_time,
        signed_at: datetime!(2026-04-01 12:02:00 UTC),
        signer_cert_der: signer_cert_der.clone(),
        timestamp_token_der: Some(timestamp_token_der),
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: None,
        signed_pdf_bytes: signed_pdf_with_dss,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let manifest = validate_package(&package).expect("archive package validates");
    assert!(
        manifest.files.iter().any(|file| {
            file.path == format!("signed/{}.pdf", sealed.document_id)
                && file.content_type == "application/pdf; profile=PAdES-B-T"
        }),
        "signed PDF remains timestamp-profiled, not advertised as legal B-LT: {manifest:?}"
    );

    let members = zip_members(&package);
    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    let report = member_json(&members, &evidence_path);
    assert_eq!(report["report_kind"], "signature_validation_evidence");
    assert_eq!(report["status"], "signed");
    assert_eq!(report["archive_export_revalidated"], false);
    let dss = &report["signature"]["dss"];
    assert_eq!(dss["basis"], "embedded_pdf_dss_catalog_inspection_only");
    assert_eq!(dss["present"], true);
    assert_eq!(dss["vri_count"], 1);
    assert_eq!(dss["certificate_count"], 1);
    assert_eq!(dss["ocsp_count"], 1);
    assert_eq!(dss["crl_count"], 1);
    assert_eq!(dss["revocation_evidence_present"], true);
    assert_eq!(dss["local_b_lt_style_evidence_present"], true);
    assert_eq!(dss["live_revocation_fetching"], false);
    assert_eq!(dss["production_b_lt_status"], "not_claimed");
    assert_eq!(dss["legal_b_lt_claimed"], false);
    assert_eq!(dss["inspection_status"], "inspected_from_signed_pdf");
    assert_eq!(
        dss["certificate_sha256"],
        json!([sha256_hex(&signer_cert_der)])
    );
    assert_eq!(dss["ocsp_sha256"], json!([sha256_hex(OCSP_DER_FIXTURE)]));
    assert_eq!(dss["crl_sha256"], json!([sha256_hex(CRL_DER_FIXTURE)]));
    let doc_timestamp = &report["signature"]["doc_timestamp"];
    assert_eq!(
        doc_timestamp["basis"],
        "embedded_pdf_doctimestamp_inspection_only"
    );
    assert_eq!(doc_timestamp["present"], false);
    assert_eq!(doc_timestamp["count"], 0);
    assert_eq!(doc_timestamp["all_imprints_valid"], false);
    assert_eq!(report["signature"]["legal_b_lta_claimed"], false);
    assert_eq!(
        report["signature"]["renewal_policy"]["status"],
        "not_configured"
    );
    assert_eq!(
        report["signature"]["renewal_policy"]["action"],
        "manual_review"
    );
    assert!(
        report["signature"].get("legal_qualification").is_none(),
        "archive evidence must not claim legal qualification: {report}"
    );
}

#[tokio::test]
async fn archive_package_reports_embedded_doc_timestamp_evidence_without_b_lta_claim() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let act_id = ActId(Uuid::parse_str(&sealed.act_id).expect("act uuid"));

    let signed_pdf_bytes = DOC_TIMESTAMP_FIXTURE_PDF.to_vec();
    let signed_pdf_digest = sha256_hex(&signed_pdf_bytes);
    let signer_cert_der = b"fixture signer certificate DER".to_vec();
    let signed = StoredSignedDocument {
        act_id,
        document_id: sealed.document_id.clone(),
        signed_pdf_digest,
        signature_family: "CartaoDeCidadao".to_owned(),
        evidentiary_level: "Qualified".to_owned(),
        trusted_list_status: Some("Granted".to_owned()),
        signer_cert_subject: Some("CN=Chancela mock signer".to_owned()),
        signing_time: datetime!(2026-04-01 12:00:00 UTC),
        signed_at: datetime!(2026-04-01 12:02:00 UTC),
        signer_cert_der,
        timestamp_token_der: Some(b"fixture timestamp token DER".to_vec()),
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: None,
        signed_pdf_bytes,
    };
    state
        .store
        .as_ref()
        .expect("store")
        .persist(|tx| tx.upsert_signed_document(&signed))
        .expect("signed document persisted");

    let package = archive_package_bytes(&state, &sealed.book_id, &token).await;
    let members = zip_members(&package);
    let evidence_path = format!("evidence/{}.json", sealed.document_id);
    let report = member_json(&members, &evidence_path);
    let signature = &report["signature"];
    let doc_timestamp = &signature["doc_timestamp"];

    assert_eq!(
        doc_timestamp["basis"],
        "embedded_pdf_doctimestamp_inspection_only"
    );
    assert_eq!(
        doc_timestamp["inspection_status"],
        "inspected_from_signed_pdf"
    );
    assert_eq!(doc_timestamp["present"], true);
    assert_eq!(doc_timestamp["count"], 1);
    assert_eq!(doc_timestamp["token_sha256"].as_array().unwrap().len(), 1);
    assert_eq!(doc_timestamp["validations"].as_array().unwrap().len(), 1);
    assert_eq!(doc_timestamp["validations"][0]["status"], "valid");
    assert_eq!(
        doc_timestamp["validations"][0]["failure_reason"],
        Value::Null
    );
    assert_eq!(doc_timestamp["all_imprints_valid"], true);
    assert_eq!(signature["renewal_policy"]["status"], "not_configured");
    assert_eq!(signature["renewal_policy"]["action"], "manual_review");
    assert_eq!(signature["legal_b_lta_claimed"], false);
    assert!(
        signature.get("current_level").is_none(),
        "archive evidence must not claim a B-LTA current level: {report}"
    );
}
