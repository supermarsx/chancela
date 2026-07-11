//! Focused persistence coverage for act working-state edits and canonical Ata document targets.
//!
//! Both journeys drive the real `chancela-server` binary over HTTP. The first proves a pre-seal
//! `PATCH /v1/acts/{id}` is durable across a server restart before the act is sealed. The second
//! proves later certidao/extrato generation does not replace the sealed Ata used by the act's
//! canonical document download and preservation bundle, including after reload from the store.

mod common;

use common::*;
use reqwest::header::HeaderMap;
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

async fn get_bytes(h: &ServerHarness, path: &str) -> (u16, String, Vec<u8>) {
    let (status, headers, bytes) = get_bytes_with_headers(h, path).await;
    let ctype = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    (status, ctype, bytes)
}

async fn get_bytes_with_headers(h: &ServerHarness, path: &str) -> (u16, HeaderMap, Vec<u8>) {
    let client = reqwest::Client::new();
    let mut req = client.get(format!("{}{}", h.base_url, path));
    if let Some(t) = h.current_token() {
        req = req.header(SESSION_HEADER, t);
    }
    let resp = req
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("read body of {path} failed: {e}"))
        .to_vec();
    (status, headers, bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
struct GeneratedDocRow {
    id: String,
    template_id: String,
    pdf_digest: String,
}

fn generated_documents_for_act(h: &ServerHarness, act_id: &str) -> Vec<GeneratedDocRow> {
    let conn =
        Connection::open(h.data_dir.join(chancela_store::DB_FILE)).expect("open e2e store db");
    let mut stmt = conn
        .prepare(
            "SELECT id, template_id, pdf_digest FROM documents \
             WHERE act_id = ?1 ORDER BY created_at ASC, rowid ASC",
        )
        .expect("prepare document query");
    let rows = stmt
        .query_map([act_id], |row| {
            Ok(GeneratedDocRow {
                id: row.get(0)?,
                template_id: row.get(1)?,
                pdf_digest: row.get(2)?,
            })
        })
        .expect("query generated documents");
    rows.map(|row| row.expect("document row")).collect()
}

async fn fill_condominium_absent_owner_contents(h: &ServerHarness, act_id: &str, token: &str) {
    let (status, body) = h
        .patch_json_auth(
            &format!("/v1/acts/{act_id}"),
            json!({
                "meeting_date": "2026-03-30",
                "meeting_time": "10:00",
                "place": "Hall do predio",
                "agenda": [{ "number": 1, "text": "Orcamento anual" }],
                "attendance_reference": "Folha de presencas",
                "deliberations": "Aprovado o orcamento anual.",
                "deliberation_items": [{
                    "agenda_number": 1,
                    "text": "Aprovado o orcamento anual.",
                    "vote": { "type": "Recorded", "em_favor": 600, "contra": 0, "abstencoes": 0 },
                    "statements": []
                }],
                "attendees": [
                    {
                        "name": "Fracao A",
                        "quality": "CondoOwner",
                        "presence": "InPerson",
                        "weight": { "Permilage": 600 }
                    },
                    {
                        "name": "Fracao B",
                        "quality": "CondoOwner",
                        "presence": "Absent",
                        "weight": { "Permilage": 400 }
                    }
                ]
            }),
            token,
        )
        .await;
    assert_eq!(status, 200, "patch condominium absent-owner act: {body}");
}

fn assert_patched_act_view(act: &Value) {
    assert_eq!(act["title"], "Ata patch persistida antes do selo");
    assert_eq!(act["meeting_date"], "2026-04-02");
    assert_eq!(act["meeting_time"], "14:30");
    assert_eq!(act["place"], "Sala do conselho");
    assert_eq!(act["mesa"]["presidente"], "Ana Presidente");
    assert_eq!(act["mesa"]["secretarios"][0], "Rui Secretario");
    assert_eq!(act["agenda"][0]["number"], 1);
    assert_eq!(
        act["agenda"][0]["text"],
        "Aprovacao das contas do exercicio"
    );
    assert_eq!(act["attendance_reference"], "Lista de presencas n.o 7");
    assert_eq!(
        act["deliberations"],
        "Aprovadas por unanimidade as contas do exercicio de 2025."
    );
}

fn assert_canonical_bundle(
    bundle: &Value,
    act_id: &str,
    ata_doc_id: &str,
    ata_digest: &str,
    ata_len: usize,
) {
    assert_eq!(bundle["act_id"], act_id);
    assert_eq!(bundle["document"]["id"], ata_doc_id);
    assert_eq!(bundle["document"]["template_id"], "csc-ata-ag/v1");
    assert_eq!(bundle["document"]["pdf_digest"], ata_digest);
    assert_eq!(bundle["pdf"]["media_type"], "application/pdf");
    assert_eq!(bundle["pdf"]["byte_length"], ata_len as u64);
    assert_eq!(
        bundle["pdf"]["download"],
        format!("/v1/acts/{act_id}/document")
    );
}

async fn sealed_csc_act(h: &ServerHarness) -> (String, String, Value) {
    let token = bootstrap_session(h).await;
    let entity_id = create_entity(
        h,
        "Encosto Estrategico, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(h, &entity_id, &token).await;
    let act_id = draft_act(h, &book_id, "Ata da Assembleia Geral Anual", Some(&token)).await;
    fill_act_contents(h, &act_id, &token).await;
    advance_to_signing(h, &act_id, Some(&token)).await;

    let (status, sealed) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "seal: {sealed}");
    assert_eq!(sealed["act"]["state"], "Sealed");
    assert_eq!(sealed["ata_number"], 1);

    (token, act_id, sealed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn act_patch_survives_restart_before_seal() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;

    let entity_id = create_entity(
        &h,
        "Persistencia Patch, S.A.",
        "503004642",
        "Lisboa",
        "SociedadeAnonima",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata em rascunho", Some(&token)).await;

    let patch = json!({
        "title": "Ata patch persistida antes do selo",
        "meeting_date": "2026-04-02",
        "meeting_time": "14:30",
        "place": "Sala do conselho",
        "mesa": { "presidente": "Ana Presidente", "secretarios": ["Rui Secretario"] },
        "agenda": [{ "number": 1, "text": "Aprovacao das contas do exercicio" }],
        "attendance_reference": "Lista de presencas n.o 7",
        "deliberations": "Aprovadas por unanimidade as contas do exercicio de 2025."
    });
    let (status, patched) = h
        .patch_json_auth(&format!("/v1/acts/{act_id}"), patch, &token)
        .await;
    assert_eq!(status, 200, "patch act: {patched}");
    assert_patched_act_view(&patched);

    h.restart().await;

    let (status, persisted) = h.get_json(&format!("/v1/acts/{act_id}")).await;
    assert_eq!(
        status, 200,
        "patched draft act should reload before sealing: {persisted}"
    );
    assert_patched_act_view(&persisted);
    assert_eq!(persisted["state"], "Draft");
    assert!(persisted["ata_number"].is_null());
    assert!(persisted["payload_digest"].is_null());

    let token = h
        .current_token()
        .expect("default session was reopened after restart");
    advance_to_signing(&h, &act_id, Some(&token)).await;

    let (status, sealed) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(
        status, 200,
        "act seals after restart using persisted patch: {sealed}"
    );
    assert_eq!(sealed["act"]["state"], "Sealed");
    assert_eq!(sealed["ata_number"], 1);
    assert_patched_act_view(&sealed["act"]);
    assert_eq!(sealed["document"]["template_id"], "csc-ata-ag/v1");
    assert_eq!(
        sealed["payload_digest"]
            .as_str()
            .expect("payload digest")
            .len(),
        64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn certidao_and_extrato_do_not_replace_canonical_ata_download_or_bundle() {
    let mut h = ServerHarness::start().await;
    let (token, act_id, sealed) = sealed_csc_act(&h).await;

    let ata_doc = &sealed["document"];
    assert_eq!(ata_doc["template_id"], "csc-ata-ag/v1", "sealed: {sealed}");
    let ata_doc_id = ata_doc["id"].as_str().expect("ata document id").to_owned();
    let ata_digest = ata_doc["pdf_digest"]
        .as_str()
        .expect("ata document digest")
        .to_owned();

    let (status, ctype, ata_pdf) = get_bytes(&h, &format!("/v1/acts/{act_id}/document")).await;
    assert_eq!(status, 200, "sealed Ata downloads");
    assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
    assert!(ata_pdf.starts_with(b"%PDF-"), "sealed Ata bytes are a PDF");
    assert_eq!(sha256_hex(&ata_pdf), ata_digest);

    let (status, bundle) = h
        .get_json(&format!("/v1/acts/{act_id}/document/bundle"))
        .await;
    assert_eq!(status, 200, "canonical bundle before extra docs: {bundle}");
    assert_canonical_bundle(&bundle, &act_id, &ata_doc_id, &ata_digest, ata_pdf.len());

    for template_id in ["csc-certidao-ata/v1", "csc-extrato-ata/v1"] {
        let (status, made) = h
            .post_json_auth(
                &format!("/v1/acts/{act_id}/document/generate?template_id={template_id}"),
                json!({}),
                &token,
            )
            .await;
        assert_eq!(status, 201, "generate {template_id}: {made}");
        assert_eq!(made["act_id"], act_id);
        assert_eq!(made["template_id"], template_id);
        assert_ne!(made["id"], ata_doc_id);
        assert_eq!(
            made["pdf_digest"].as_str().expect("generated digest").len(),
            64
        );

        let (status, ctype, current_pdf) =
            get_bytes(&h, &format!("/v1/acts/{act_id}/document")).await;
        assert_eq!(
            status, 200,
            "{template_id} must not replace the Ata download"
        );
        assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
        assert_eq!(
            current_pdf, ata_pdf,
            "{template_id} generation must leave the canonical Ata bytes in place"
        );

        let (status, bundle) = h
            .get_json(&format!("/v1/acts/{act_id}/document/bundle"))
            .await;
        assert_eq!(status, 200, "bundle after {template_id}: {bundle}");
        assert_canonical_bundle(&bundle, &act_id, &ata_doc_id, &ata_digest, ata_pdf.len());
    }

    h.restart().await;

    let (status, ctype, reloaded_pdf) = get_bytes(&h, &format!("/v1/acts/{act_id}/document")).await;
    assert_eq!(status, 200, "canonical Ata downloads after restart");
    assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
    assert_eq!(
        reloaded_pdf, ata_pdf,
        "store reload keeps the sealed Ata as the canonical document"
    );

    let (status, bundle) = h
        .get_json(&format!("/v1/acts/{act_id}/document/bundle"))
        .await;
    assert_eq!(status, 200, "canonical bundle after restart: {bundle}");
    assert_canonical_bundle(&bundle, &act_id, &ata_doc_id, &ata_digest, ata_pdf.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(
    not(feature = "e2e"),
    ignore = "composed-system e2e: spawns the real server binary (run with --features e2e)"
)]
async fn condominium_absent_owner_communication_auto_generates_and_keeps_canonical_ata() {
    let mut h = ServerHarness::start().await;
    let token = bootstrap_session(&h).await;
    let entity_id = create_entity(
        &h,
        "Condominio Edificio Central",
        "503004642",
        "Lisboa",
        "Condominio",
        &token,
    )
    .await;
    let book_id = open_book(&h, &entity_id, &token).await;
    let act_id = draft_act(&h, &book_id, "Ata da assembleia", Some(&token)).await;
    fill_condominium_absent_owner_contents(&h, &act_id, &token).await;
    advance_to_signing(&h, &act_id, Some(&token)).await;

    let (status, sealed) = h
        .post_json_auth(&format!("/v1/acts/{act_id}/seal"), json!({}), &token)
        .await;
    assert_eq!(status, 200, "seal condominium act: {sealed}");
    assert_eq!(
        sealed["document"]["template_id"],
        "condominio-ata-assembleia/v1"
    );
    let ata_doc_id = sealed["document"]["id"].as_str().expect("ata doc id");
    let ata_digest = sealed["document"]["pdf_digest"]
        .as_str()
        .expect("ata digest");

    let (status, ctype, ata_pdf) = get_bytes(&h, &format!("/v1/acts/{act_id}/document")).await;
    assert_eq!(status, 200, "canonical condominium Ata downloads");
    assert!(ctype.starts_with("application/pdf"), "ctype={ctype}");
    assert_eq!(sha256_hex(&ata_pdf), ata_digest);

    let docs = generated_documents_for_act(&h, &act_id);
    let communication = docs
        .iter()
        .find(|doc| doc.template_id == "condominio-comunicacao-ausentes/v1")
        .unwrap_or_else(|| panic!("absent-owner communication generated: {docs:?}"));
    assert_ne!(communication.id, ata_doc_id);
    assert_ne!(communication.pdf_digest, ata_digest);

    let (status, headers, communication_pdf) =
        get_bytes_with_headers(&h, &format!("/v1/documents/generated/{}", communication.id)).await;
    assert_eq!(
        status, 200,
        "generated absent-owner communication downloads"
    );
    assert_eq!(
        headers
            .get("x-chancela-template-id")
            .and_then(|v| v.to_str().ok()),
        Some("condominio-comunicacao-ausentes/v1")
    );
    assert_eq!(
        headers
            .get("x-chancela-dispatch-evidence-status")
            .and_then(|v| v.to_str().ok()),
        Some("required_pending")
    );
    assert_eq!(
        headers
            .get("x-chancela-dispatch-evidence-attached")
            .and_then(|v| v.to_str().ok()),
        Some("false")
    );
    assert_eq!(sha256_hex(&communication_pdf), communication.pdf_digest);

    let (status, events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(status, 200, "ledger events: {events}");
    let generated_events = events
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| {
            e["kind"] == "document.generated"
                && e["scope"]
                    .as_str()
                    .is_some_and(|scope| scope.contains(&format!("/act:{act_id}")))
        })
        .count();
    assert_eq!(
        generated_events, 2,
        "Ata + absent-owner communication document events: {events}"
    );

    h.restart().await;

    let (status, _ctype, reloaded_ata) =
        get_bytes(&h, &format!("/v1/acts/{act_id}/document")).await;
    assert_eq!(status, 200, "canonical Ata still downloads after restart");
    assert_eq!(reloaded_ata, ata_pdf);
    let (status, headers, reloaded_communication) =
        get_bytes_with_headers(&h, &format!("/v1/documents/generated/{}", communication.id)).await;
    assert_eq!(status, 200, "communication still downloads after restart");
    assert_eq!(
        headers
            .get("x-chancela-dispatch-evidence-status")
            .and_then(|v| v.to_str().ok()),
        Some("required_pending")
    );
    assert_eq!(reloaded_communication, communication_pdf);

    let (status, reloaded_events) = h.get_json("/v1/ledger/events").await;
    assert_eq!(
        status, 200,
        "ledger events after restart: {reloaded_events}"
    );
    let reloaded_generated_events = reloaded_events
        .as_array()
        .expect("reloaded events array")
        .iter()
        .filter(|e| {
            e["kind"] == "document.generated"
                && e["scope"]
                    .as_str()
                    .is_some_and(|scope| scope.contains(&format!("/act:{act_id}")))
        })
        .count();
    assert_eq!(
        reloaded_generated_events, 2,
        "Ata + absent-owner communication document events after restart: {reloaded_events}"
    );
}
