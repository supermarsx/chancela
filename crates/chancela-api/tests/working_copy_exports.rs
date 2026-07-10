use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use chancela_api::{AppState, router};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("chancela-api-working-copy-{}", Uuid::new_v4()));
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
    act_id: String,
    document_id: String,
    pdf_digest: String,
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

async fn send_raw(state: &AppState, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let resp = router(state.clone())
        .oneshot(req)
        .await
        .expect("router responds");
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, headers, bytes)
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
                json!({ "username": "working.copy.owner", "display_name": "Working Copy Owner" })
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
            .body(Body::from(json!({ "user_id": user_id }).to_string()))
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "open session: {session}");
    session["token"].as_str().expect("token").to_owned()
}

async fn draft_act_in_open_book(state: &AppState, token: &str) -> String {
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
    let entity_id = entity["id"].as_str().expect("entity id");

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
    let book_id = book["id"].as_str().expect("book id");

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
    act["id"].as_str().expect("act id").to_owned()
}

async fn seal_act(state: &AppState, token: &str) -> SealedAct {
    let act_id = draft_act_in_open_book(state, token).await;

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
        json_req("POST", &format!("/v1/acts/{act_id}/seal"), token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seal: {sealed}");

    SealedAct {
        act_id,
        document_id: sealed["document"]["id"]
            .as_str()
            .expect("document id")
            .to_owned(),
        pdf_digest: sealed["document"]["pdf_digest"]
            .as_str()
            .expect("pdf digest")
            .to_owned(),
    }
}

async fn ledger_events(state: &AppState, token: &str) -> Value {
    let (status, events) = send(state, get_req("/v1/ledger/events?limit=1000", token)).await;
    assert_eq!(status, StatusCode::OK, "ledger events: {events}");
    events
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> &str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .expect("header is present")
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

#[tokio::test]
async fn sealed_act_working_copy_export_matrix_is_deterministic_and_read_only() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let sealed = seal_act(&state, &token).await;
    let events_before = ledger_events(&state, &token).await;

    for (format, expected_type, expected_ext, expected_notice) in [
        (
            "md",
            "text/markdown; charset=utf-8",
            ".md",
            "Markdown export",
        ),
        (
            "txt",
            "text/plain; charset=utf-8",
            ".txt",
            "plain-text export",
        ),
        ("html", "text/html; charset=utf-8", ".html", "HTML export"),
        ("rtf", "application/rtf", ".rtf", "RTF export"),
    ] {
        let uri = format!(
            "/v1/acts/{}/document/working-copy?format={format}",
            sealed.act_id
        );
        let (status, headers, first) = send_raw(&state, get_req(&uri, &token)).await;
        assert_eq!(status, StatusCode::OK, "first {format} export");
        assert_eq!(
            header_value(&headers, header::CONTENT_TYPE),
            expected_type,
            "{format} content-type"
        );
        let disposition = header_value(&headers, header::CONTENT_DISPOSITION);
        assert!(
            disposition.contains("attachment;")
                && disposition.contains("working-copy")
                && disposition.contains(expected_ext),
            "{format} filename labels working copy: {disposition}"
        );

        let (status, _, second) = send_raw(&state, get_req(&uri, &token)).await;
        assert_eq!(status, StatusCode::OK, "second {format} export");
        assert_eq!(second, first, "{format} export bytes are deterministic");

        let body = String::from_utf8(first).expect("textual working copy is utf-8");
        assert!(body.contains("WORKING COPY - NON-EVIDENTIARY"));
        assert!(body.contains(expected_notice));
        assert!(body.contains("not the preserved signed original"));
        assert!(body.contains(&sealed.document_id));
        assert!(body.contains(&sealed.pdf_digest));
        assert!(body.contains("Ata da AG anual"));
        assert!(body.contains("Sede social"));
        assert!(
            !body.starts_with("%PDF-"),
            "{format} export is not canonical PDF bytes"
        );
    }

    let odt_uri = format!(
        "/v1/acts/{}/document/working-copy?format=odt",
        sealed.act_id
    );
    let (status, headers, first_odt) = send_raw(&state, get_req(&odt_uri, &token)).await;
    assert_eq!(status, StatusCode::OK, "first ODT export");
    assert_eq!(
        header_value(&headers, header::CONTENT_TYPE),
        "application/vnd.oasis.opendocument.text"
    );
    let disposition = header_value(&headers, header::CONTENT_DISPOSITION);
    assert!(
        disposition.contains("working-copy") && disposition.contains(".odt"),
        "ODT filename labels working copy: {disposition}"
    );
    let (status, _, second_odt) = send_raw(&state, get_req(&odt_uri, &token)).await;
    assert_eq!(status, StatusCode::OK, "second ODT export");
    assert_eq!(second_odt, first_odt, "ODT export bytes are deterministic");

    let odt_members = zip_members(&first_odt);
    let mimetype = String::from_utf8(
        odt_members
            .get("mimetype")
            .expect("ODT mimetype member")
            .clone(),
    )
    .expect("mimetype is utf-8");
    assert_eq!(mimetype, "application/vnd.oasis.opendocument.text");
    let content_xml = String::from_utf8(
        odt_members
            .get("content.xml")
            .expect("ODT content.xml member")
            .clone(),
    )
    .expect("content.xml is utf-8");
    assert!(content_xml.contains("WORKING COPY - NON-EVIDENTIARY"));
    assert!(content_xml.contains("not the preserved signed original"));
    assert!(content_xml.contains(&sealed.document_id));
    assert!(content_xml.contains(&sealed.pdf_digest));

    let docx_uri = format!("/v1/acts/{}/document/office", sealed.act_id);
    let (status, headers, first_docx) = send_raw(&state, get_req(&docx_uri, &token)).await;
    assert_eq!(status, StatusCode::OK, "first DOCX export");
    assert_eq!(
        header_value(&headers, header::CONTENT_TYPE),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    let disposition = header_value(&headers, header::CONTENT_DISPOSITION);
    assert!(
        disposition.contains("office-working-copy") && disposition.contains(".docx"),
        "DOCX filename labels office working copy: {disposition}"
    );
    let (status, _, second_docx) = send_raw(&state, get_req(&docx_uri, &token)).await;
    assert_eq!(status, StatusCode::OK, "second DOCX export");
    assert_eq!(
        second_docx, first_docx,
        "DOCX export bytes are deterministic"
    );

    let docx_members = zip_members(&first_docx);
    let document_xml = String::from_utf8(
        docx_members
            .get("word/document.xml")
            .expect("DOCX document part")
            .clone(),
    )
    .expect("document.xml is utf-8");
    assert!(document_xml.contains("WORKING COPY - NON-EVIDENTIARY"));
    assert!(document_xml.contains("not the preserved signed original"));
    assert!(document_xml.contains(&sealed.document_id));
    assert!(document_xml.contains(&sealed.pdf_digest));

    let events_after = ledger_events(&state, &token).await;
    assert_eq!(
        events_after, events_before,
        "working-copy downloads must not append ledger events"
    );
}

#[tokio::test]
async fn unsupported_and_unsealed_working_copy_requests_fail_without_ledger_mutation() {
    let dir = TempDir::new();
    let state = AppState::with_data_dir(dir.0.clone());
    let token = bootstrap(&state).await;
    let draft_act_id = draft_act_in_open_book(&state, &token).await;
    let sealed = seal_act(&state, &token).await;
    let events_before = ledger_events(&state, &token).await;

    let (status, _, _) = send_raw(
        &state,
        get_req(
            &format!(
                "/v1/acts/{}/document/working-copy?format=pdf",
                sealed.act_id
            ),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unsupported working-copy format is refused"
    );

    let (status, _, _) = send_raw(
        &state,
        get_req(
            &format!("/v1/acts/{draft_act_id}/document/working-copy?format=md"),
            &token,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "draft act in an open book has no preserved working-copy export"
    );

    let events_after = ledger_events(&state, &token).await;
    assert_eq!(
        events_after, events_before,
        "refused working-copy requests must not append ledger events"
    );
}
