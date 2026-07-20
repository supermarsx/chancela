//! Reading order of the internal preservation package.
//!
//! The package's ZIP members are named by document id and the format requires them to be
//! path-sorted, so the member order can never carry the order in which the book reads. The order
//! lives in the inventory instead — in the `evidence/index.json` `documents` array and in each
//! `metadata/{id}.json` sidecar. These tests build a real book (termo de abertura, several sealed
//! atas, termo de encerramento) through the API and assert the package presents it as a book:
//! abertura → atas by `ata_number` → encerramento.

mod common;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use chancela_api::{AppState, router};
use common::TEST_PASSWORD;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("chancela-api-archive-order-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("temp dir created");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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

fn json_req(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-chancela-session", token)
        .body(Body::from(body.to_string()))
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
                    "username": "archive.order.owner",
                    "display_name": "Archive Order Owner",
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

/// Open an entity + book. Opening the book generates and persists the termo de abertura.
async fn open_book(state: &AppState, token: &str) -> String {
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
    book["id"].as_str().expect("book id").to_owned()
}

/// Draft, advance and seal one act in `book_id`, returning its document id. Sealing assigns the
/// next `ata_number`, so calling this repeatedly numbers the atas 1..N in call order.
async fn seal_ata(state: &AppState, token: &str, book_id: &str, ordinal: u32) -> String {
    let (status, act) = send(
        state,
        json_req(
            "POST",
            "/v1/acts",
            token,
            json!({
                "book_id": book_id,
                "title": format!("Ata da AG {ordinal}"),
                "channel": "Physical"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "act {ordinal}: {act}");
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
    assert_eq!(status, StatusCode::OK, "patch act {ordinal}: {body}");

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
        assert_eq!(status, StatusCode::OK, "advance {ordinal} to {to}: {body}");
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
    assert_eq!(status, StatusCode::OK, "seal {ordinal}: {sealed}");
    assert_eq!(
        sealed["act"]["ata_number"], ordinal,
        "seal {ordinal} assigns ata number {ordinal}: {sealed}"
    );
    sealed["document"]["id"]
        .as_str()
        .expect("document id")
        .to_owned()
}

/// Close the book, which generates and persists the termo de encerramento.
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

async fn archive_package_bytes(state: &AppState, book_id: &str, token: &str) -> Vec<u8> {
    let req = Request::builder()
        .uri(format!("/v1/books/{book_id}/archive/package"))
        .header("x-chancela-session", token)
        .body(Body::empty())
        .expect("request builds");
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::OK, "archive package status");
    to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
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

fn member_json(members: &BTreeMap<String, Vec<u8>>, path: &str) -> Value {
    serde_json::from_slice(members.get(path).unwrap_or_else(|| panic!("member {path}")))
        .unwrap_or_else(|e| panic!("member {path} is JSON: {e}"))
}

const ATA_COUNT: u32 = 5;

/// Build a book with a termo de abertura, `ATA_COUNT` sealed atas and a termo de encerramento, and
/// return the package's `evidence/index.json` documents array plus the sealed atas' document ids in
/// ata order.
async fn ordered_index(state: &AppState) -> (Vec<Value>, BTreeMap<String, Vec<u8>>, Vec<String>) {
    let token = bootstrap(state).await;
    let book_id = open_book(state, &token).await;
    let mut ata_document_ids = Vec::new();
    for ordinal in 1..=ATA_COUNT {
        ata_document_ids.push(seal_ata(state, &token, &book_id, ordinal).await);
    }
    close_book(state, &token, &book_id).await;

    let members = zip_members(&archive_package_bytes(state, &book_id, &token).await);
    let index = member_json(&members, "evidence/index.json");
    let documents = index["documents"]
        .as_array()
        .expect("documents array")
        .clone();
    (documents, members, ata_document_ids)
}

#[tokio::test]
async fn archive_package_orders_documents_the_way_the_book_reads() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let (documents, _members, ata_document_ids) = ordered_index(&state).await;

    // Abertura + 5 atas + encerramento. The old comparator sorted by `owner_kind` first, and
    // "act" < "book", so both termos landed after every ata; this assertion fails against it
    // regardless of which ids the run happens to generate.
    let positions = documents
        .iter()
        .map(|doc| doc["position"].as_str().expect("position").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        positions,
        vec![
            "termo_abertura",
            "ata",
            "ata",
            "ata",
            "ata",
            "ata",
            "termo_encerramento",
        ],
        "package must read abertura → atas → encerramento: {documents:#?}"
    );

    // The atas carry the book's own numbering, in order — not the order their random document ids
    // happen to sort in.
    let ata_numbers = documents
        .iter()
        .filter(|doc| doc["position"] == "ata")
        .map(|doc| doc["ata_number"].as_u64().expect("ata number"))
        .collect::<Vec<_>>();
    assert_eq!(
        ata_numbers,
        (1..=u64::from(ATA_COUNT)).collect::<Vec<_>>(),
        "atas must appear in ata_number order: {documents:#?}"
    );

    // ...and the entries are the sealed atas' own documents, in the order they were sealed.
    let ata_ids = documents
        .iter()
        .filter(|doc| doc["position"] == "ata")
        .map(|doc| doc["document_id"].as_str().expect("document id").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        ata_ids, ata_document_ids,
        "ata entries must be the sealed atas in seal order"
    );

    // `reading_order` is 1..N over the whole book, so a recipient can bind the id-named members
    // back into book order without re-deriving anything.
    let reading_order = documents
        .iter()
        .map(|doc| doc["reading_order"].as_u64().expect("reading order"))
        .collect::<Vec<_>>();
    assert_eq!(
        reading_order,
        (1..=documents.len() as u64).collect::<Vec<_>>(),
        "reading_order must be a dense 1-based sequence in array order"
    );

    // The termos are book-level instruments, so they carry no ata number and no act id.
    for doc in documents.iter().filter(|doc| doc["position"] != "ata") {
        assert!(
            doc["ata_number"].is_null(),
            "termo has no ata number: {doc}"
        );
        assert!(doc["act_id"].is_null(), "termo has no act id: {doc}");
    }
}

#[tokio::test]
async fn archive_package_metadata_sidecars_agree_with_the_evidence_index_order() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(&dir.0);
    let (documents, members, _) = ordered_index(&state).await;

    // An index that disagreed with the per-document sidecars would be a new inconsistency, so the
    // ordinal is asserted on both sides for every document in the package.
    for entry in &documents {
        let document_id = entry["document_id"].as_str().expect("document id");
        let sidecar = member_json(&members, &format!("metadata/{document_id}.json"));
        assert_eq!(
            sidecar["book_order"]["reading_order"], entry["reading_order"],
            "sidecar and index disagree on reading order for {document_id}"
        );
        assert_eq!(
            sidecar["book_order"]["position"], entry["position"],
            "sidecar and index disagree on position for {document_id}"
        );
        assert_eq!(
            sidecar["book_order"]["ata_number"], entry["ata_number"],
            "sidecar and index disagree on ata number for {document_id}"
        );
    }
}
