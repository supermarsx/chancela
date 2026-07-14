//! Postgres backend integration stubs (wp14 Phase 1 / 1.5).
//!
//! These tests require a live PostgreSQL reachable at `DATABASE_URL` and are therefore
//! `#[ignore]`d by default AND compiled only under the off-by-default `postgres` feature, so the
//! standard `cargo test -p chancela-store` (and the desktop/browser builds) stay Postgres-free and
//! offline. The full backend-agnostic round-trip suite (persist → reload → ledger-replay parity
//! across `{sqlite, postgres}`) runs in the testcontainers lane / compose smoke (plan §8, Phase 3).
//!
//! Run locally against a throwaway database with, e.g.:
//! ```sh
//! DATABASE_URL=postgres://chancela:chancela@localhost:5432/chancela_test \
//!   cargo test -p chancela-store --features postgres -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: the backend holds a **process-lifetime session advisory lock**
//! on a single writer connection (§4), so two backends opened concurrently against the same
//! database would contend on that lock. Run the ignored tests serially.
#![cfg(feature = "postgres")]

use chancela_core::ActId;
use chancela_ledger::Ledger;
use chancela_store::{
    LedgerEventPageQuery, PendingCmdSession, Store, StoreBackendSelection, StoredDocument,
    StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocument, StoredImportedDocumentMeta, StoredImportedDocumentReviewStatus,
    StoredPaperBookImport, StoredPaperBookImportMeta, StoredPaperBookOcrConversionDossier,
    StoredPaperBookOcrConversionExecutionArtifact, StoredPaperBookOcrDraft,
    StoredPaperBookOcrPageSpan, StoredPaperBookOcrReviewStatus, StoredPaperBookOcrStatus,
    StoredSignedDocument,
};
use time::OffsetDateTime;

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
}

fn ts(secs: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(secs).unwrap()
}

/// Open the Postgres backend, append one ledger event through the frozen `persist(|tx| …)` closure,
/// and prove the boot `load` replay reconstructs the same single-event chain and verifies clean.
/// This exercises the §4 atomic-append + single-writer write path and the boot replay path.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn persist_and_reload_event_roundtrips_on_postgres() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");

    let mut ledger = Ledger::new();
    let event = ledger
        .append(
            "amelia.marques",
            "application",
            "app.started",
            None,
            b"postgres-roundtrip",
        )
        .clone();
    store
        .persist(|tx| tx.append_event(&event))
        .expect("persist event on postgres");

    let loaded = store.load().expect("reload from postgres");
    assert_eq!(loaded.ledger.len(), 1, "one event should replay");
    assert!(
        loaded.chain_status.is_ok(),
        "replayed chain must verify clean"
    );
}

/// Exercise every runtime write/read path ported to Postgres in Phase 1.5: the blob document reads,
/// signed documents, follow-ups, imported documents + append-only review history (the
/// `GENERATED ALWAYS AS IDENTITY` surrogate id), dispatch evidence idempotency, pending-CMD
/// sessions, the paper-book import + OCR draft/review/dossier/execution-artifact chain (the
/// `bool`→`BIGINT` flag mapping), the paged ledger read, and the `meta` `instance_id` stamp.
///
/// One test so it can run alongside the boot-replay test serially without contending on the writer
/// advisory lock.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn runtime_reads_and_writes_roundtrip_on_postgres() {
    let Some(database_url) = database_url() else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");

    // The meta stamp minted a stable, non-empty instance id.
    assert!(!store.instance_id().expect("instance_id").is_empty());

    let act_id = ActId(uuid::Uuid::new_v4());

    // --- Generated document (BYTEA blob + by-act / by-id reads) ---
    let doc = StoredDocument {
        id: format!("doc-{}", uuid::Uuid::new_v4()),
        act_id,
        template_id: "csc-ata-ag/v1".to_string(),
        pdf_digest: "deadbeef".to_string(),
        profile: "csc/sq".to_string(),
        created_at: ts(1_770_000_000),
        pdf_bytes: b"%PDF-1.7 fake".to_vec(),
    };
    store.persist(|tx| tx.upsert_document(&doc)).unwrap();
    assert_eq!(store.document_for_act(act_id).unwrap().as_ref(), Some(&doc));
    assert_eq!(store.document_by_id(&doc.id).unwrap().as_ref(), Some(&doc));
    assert_eq!(store.documents_for_act(act_id).unwrap(), vec![doc.clone()]);

    // --- Signed document (multiple BYTEA + nullable columns) ---
    let signed = StoredSignedDocument {
        act_id,
        document_id: doc.id.clone(),
        signed_pdf_digest: "abc123".to_string(),
        signature_family: "ChaveMovelDigital".to_string(),
        evidentiary_level: "Qualified".to_string(),
        trusted_list_status: Some("Granted".to_string()),
        signer_cert_subject: Some("CN=Amelia Marques".to_string()),
        signing_time: ts(1_750_000_000),
        signed_at: ts(1_750_000_050),
        signer_cert_der: vec![0x30, 0x82, 0x01, 0x02],
        timestamp_token_der: Some(vec![0x30, 0x03, 0x01, 0x01, 0xff]),
        timestamp_trust_report_json: None,
        signer_capacity_evidence_json: Some(r#"{"k":"v"}"#.to_string()),
        signed_pdf_bytes: b"%PDF-1.7 signed".to_vec(),
    };
    store
        .persist(|tx| tx.upsert_signed_document(&signed))
        .unwrap();
    assert_eq!(
        store.signed_document_for_act(act_id).unwrap().as_ref(),
        Some(&signed)
    );
    assert_eq!(
        store.all_signed_documents().unwrap().get(&act_id),
        Some(&signed)
    );

    // --- Follow-up (nullable BIGINT agenda/deliberation + DATE) ---
    let follow_up = StoredFollowUp {
        id: format!("fu-{}", uuid::Uuid::new_v4()),
        act_id,
        agenda_number: Some(1),
        deliberation_index: Some(0),
        title: "Entregar certidao".to_string(),
        detail: Some("detalhe".to_string()),
        due_date: Some(time::macros::date!(2026 - 04 - 30)),
        assignee: Some("amelia.marques".to_string()),
        assignee_display: Some("Amelia Marques".to_string()),
        status: StoredFollowUpStatus::Open,
        created_at: ts(1_790_000_000),
        created_by: "rui.secretario".to_string(),
        completed_at: None,
        completed_by: None,
    };
    store.persist(|tx| tx.upsert_follow_up(&follow_up)).unwrap();
    assert_eq!(
        store.follow_up(&follow_up.id).unwrap().as_ref(),
        Some(&follow_up)
    );
    assert_eq!(store.follow_ups_for_act(act_id).unwrap(), vec![follow_up]);

    // --- Imported document + append-only review history (IDENTITY id) ---
    let import_bytes = b"imported evidence bytes";
    let imported = StoredImportedDocument {
        meta: StoredImportedDocumentMeta {
            id: format!("imp-{}", uuid::Uuid::new_v4()),
            act_id: Some(act_id),
            filename: Some("evidence.pdf".to_string()),
            declared_content_type: Some("application/pdf".to_string()),
            detected_content_type: "application/pdf".to_string(),
            sha256: "aa".repeat(32),
            size_bytes: import_bytes.len(),
            imported_at: ts(1_780_000_000),
            imported_by: "amelia.marques".to_string(),
            operator_review_status: StoredImportedDocumentReviewStatus::OperatorReviewRequired,
            operator_reviewed_at: None,
            operator_reviewed_by: None,
            operator_review_note: None,
            operator_acknowledged_guardrail_ids: Vec::new(),
        },
        bytes: import_bytes.to_vec(),
    };
    let imported_id = imported.meta.id.clone();
    store
        .persist(|tx| tx.upsert_imported_document(&imported))
        .unwrap();
    assert_eq!(
        store.imported_document(&imported_id).unwrap().as_ref(),
        Some(&imported)
    );
    assert_eq!(store.imported_documents(Some(act_id)).unwrap().len(), 1);

    // Two review transitions → two append-only history rows with server-assigned ascending ids.
    store
        .persist(|tx| {
            tx.review_imported_document(
                &imported_id,
                StoredImportedDocumentReviewStatus::ReviewedNonCanonicalOriginalOnly,
                Some(ts(1_780_000_100)),
                Some("amelia.marques"),
                Some("kept as evidence"),
                &["g1".to_string()],
            )
        })
        .unwrap();
    store
        .persist(|tx| {
            tx.review_imported_document(
                &imported_id,
                StoredImportedDocumentReviewStatus::RejectedNonCanonicalEvidence,
                Some(ts(1_780_000_200)),
                Some("rui.secretario"),
                None,
                &[],
            )
        })
        .unwrap();
    let history = store
        .imported_document_review_history(&imported_id)
        .unwrap();
    assert_eq!(history.len(), 2, "two review decisions recorded");
    assert!(history[0].id < history[1].id, "IDENTITY ids ascend");

    // --- Dispatch evidence idempotency (ON CONFLICT DO NOTHING) ---
    let evidence = StoredGeneratedDocumentDispatchEvidence {
        document_id: doc.id.clone(),
        idempotency_key: "idem-1".to_string(),
        act_id,
        template_id: "condominio-comunicacao-ausentes/v1".to_string(),
        actor: "amelia.marques".to_string(),
        dispatched_at: ts(1_780_000_300),
        channel: Some("RegisteredLetter".to_string()),
        reference: Some("RR1PT".to_string()),
        evidence_reference: None,
        imported_document_id: None,
        recipients: vec!["Fracao B".to_string()],
        operator_note: None,
        recorded_at: ts(1_780_000_301),
    };
    let first = store
        .persist_result(|tx| tx.upsert_generated_document_dispatch_evidence(&evidence))
        .unwrap();
    let second = store
        .persist_result(|tx| tx.upsert_generated_document_dispatch_evidence(&evidence))
        .unwrap();
    use chancela_store::GeneratedDocumentDispatchEvidenceUpsert::{Existing, Inserted};
    assert!(matches!(first, Inserted(_)), "first insert is new");
    assert!(matches!(second, Existing(_)), "retry observes existing row");
    assert_eq!(
        store
            .generated_document_dispatch_evidence(&doc.id)
            .unwrap()
            .len(),
        1
    );

    // --- Pending CMD session (upsert / read / delete) ---
    let session = PendingCmdSession {
        session_id: format!("sess-{}", uuid::Uuid::new_v4()),
        act_id,
        actor: "amelia.marques".to_string(),
        status: "otp_pending".to_string(),
        masked_phone: "+351 9•••••678".to_string(),
        doc_name: "ata.pdf".to_string(),
        signer_capacity_evidence_json: None,
        session_json: r#"{"process_id":"p1"}"#.to_string(),
        prepared_json: r#"{"prepared":true}"#.to_string(),
        created_at: ts(1_750_000_000),
        expires_at: ts(1_750_000_300),
    };
    let session_id = session.session_id.clone();
    store
        .persist(|tx| tx.upsert_pending_cmd_session(&session))
        .unwrap();
    assert_eq!(
        store.pending_cmd_session(&session_id).unwrap().as_ref(),
        Some(&session)
    );
    store
        .persist(|tx| tx.delete_pending_cmd_session(&session_id))
        .unwrap();
    assert!(store.pending_cmd_session(&session_id).unwrap().is_none());

    // --- Paper-book import + OCR draft/review/dossier/execution-artifact (bool→BIGINT flags) ---
    let pb_bytes = b"scanned paper book bytes";
    let import_id = format!("pb-{}", uuid::Uuid::new_v4());
    let paper_import = StoredPaperBookImport {
        meta: StoredPaperBookImportMeta {
            import_id: import_id.clone(),
            entity_ref: "entity-legacy-001".to_string(),
            entity_name: "Encosto Estrategico Lda".to_string(),
            entity_nipc: "503004642".to_string(),
            book_ref: "ag-book-1968-1971".to_string(),
            date_from: time::macros::date!(1968 - 01 - 01),
            date_to: time::macros::date!(1971 - 12 - 31),
            page_count: 240,
            page_from: 1,
            page_to: 240,
            original_number_from: Some(1),
            original_number_to: Some(15),
            sha256: "bb".repeat(32),
            size_bytes: pb_bytes.len(),
            content_type: "application/pdf".to_string(),
            source_filename: Some("ag-1968-1971.pdf".to_string()),
            notes: Some("Scanned minute book.".to_string()),
            imported_at: ts(1_780_000_001),
            imported_by: "amelia.marques".to_string(),
            ocr_status: StoredPaperBookOcrStatus::NotRun,
        },
        bytes: pb_bytes.to_vec(),
    };
    store
        .persist(|tx| tx.upsert_paper_book_import(&paper_import))
        .unwrap();
    assert_eq!(
        store.paper_book_import(&import_id).unwrap().as_ref(),
        Some(&paper_import)
    );
    assert_eq!(store.paper_book_imports(None).unwrap().len(), 1);

    // OCR lifecycle marker (Store-level UPDATE returning changed).
    assert!(
        store
            .update_paper_book_import_ocr_status(&import_id, StoredPaperBookOcrStatus::Completed)
            .unwrap()
    );

    let draft_id = format!("draft-{}", uuid::Uuid::new_v4());
    let mut draft = StoredPaperBookOcrDraft {
        draft_id: draft_id.clone(),
        import_id: import_id.clone(),
        extracted_text: Some("Ata transcrita.".to_string()),
        text_digest: Some("cc".repeat(32)),
        page_spans: vec![
            StoredPaperBookOcrPageSpan {
                start_page: 1,
                end_page: 3,
            },
            StoredPaperBookOcrPageSpan {
                start_page: 7,
                end_page: 7,
            },
        ],
        confidence: Some(0.82),
        engine_name: "fixture-ocr".to_string(),
        engine_version: Some("0.0.1".to_string()),
        created_at: ts(1_780_000_002),
        created_by: "amelia.marques".to_string(),
        review_status: StoredPaperBookOcrReviewStatus::Unreviewed,
        reviewed_at: None,
        reviewed_by: None,
        review_note: None,
        superseded_by: None,
    };
    store
        .persist(|tx| tx.upsert_paper_book_ocr_draft(&draft))
        .unwrap();
    // Accept the draft so the dossier/artifact invariants hold.
    store
        .persist(|tx| {
            tx.review_paper_book_ocr_draft(
                &draft_id,
                StoredPaperBookOcrReviewStatus::Accepted,
                Some(ts(1_780_000_003)),
                Some("rui.secretario"),
                None,
                None,
            )
        })
        .unwrap();
    draft.review_status = StoredPaperBookOcrReviewStatus::Accepted;
    draft.reviewed_at = Some(ts(1_780_000_003));
    draft.reviewed_by = Some("rui.secretario".to_string());
    assert_eq!(
        store.paper_book_ocr_draft(&draft_id).unwrap().as_ref(),
        Some(&draft)
    );

    let dossier_id = format!("dossier-{}", uuid::Uuid::new_v4());
    let dossier = StoredPaperBookOcrConversionDossier {
        dossier_id: dossier_id.clone(),
        import_id: import_id.clone(),
        draft_id: draft_id.clone(),
        source_text_digest: draft.text_digest.clone(),
        source_page_spans: draft.page_spans.clone(),
        source_review_status: StoredPaperBookOcrReviewStatus::Accepted,
        source_reviewed_at: draft.reviewed_at,
        source_reviewed_by: draft.reviewed_by.clone(),
        created_at: ts(1_780_000_004),
        created_by: "rui.secretario".to_string(),
    };
    store
        .persist_result(|tx| tx.upsert_paper_book_ocr_conversion_dossier(&dossier))
        .unwrap();
    assert_eq!(
        store
            .paper_book_ocr_conversion_dossier_for_draft(&import_id, &draft_id)
            .unwrap()
            .as_ref(),
        Some(&dossier)
    );

    let artifact_id = format!("artifact-{}", uuid::Uuid::new_v4());
    let target_act_id = uuid::Uuid::new_v4().to_string();
    let artifact = StoredPaperBookOcrConversionExecutionArtifact {
        artifact_id: artifact_id.clone(),
        import_id: import_id.clone(),
        draft_id: draft_id.clone(),
        dossier_id: None,
        source_text_digest: draft.text_digest.clone(),
        source_page_spans: draft.page_spans.clone(),
        source_review_status: StoredPaperBookOcrReviewStatus::Accepted,
        source_reviewed_at: draft.reviewed_at,
        source_reviewed_by: draft.reviewed_by.clone(),
        target_act_id: target_act_id.clone(),
        target_act_state: "Draft".to_string(),
        mutable_draft_act_created: true,
        created_at: ts(1_780_000_005),
        created_by: "rui.secretario".to_string(),
        canonical_conversion_claimed: false,
        canonical_minutes_claimed: false,
        canonical_act_created: false,
        canonical_document_created: false,
        signed_document_created: false,
        archive_package_created: false,
        pdfa_created: false,
        pdfua_created: false,
        signature_created: false,
        seal_created: false,
        archive_certification_claimed: false,
        legal_validity_claimed: false,
        source_extracted_text_in_artifact: false,
        source_extracted_text_in_ledger_event: false,
    };
    store
        .persist_result(|tx| tx.upsert_paper_book_ocr_conversion_execution_artifact(&artifact))
        .unwrap();
    let stored_artifact = store
        .paper_book_ocr_conversion_execution_artifact(&import_id, &draft_id, &target_act_id)
        .unwrap()
        .expect("artifact present");
    assert_eq!(stored_artifact, artifact);
    // Bind a dossier id to the artifacts and confirm the flags survive the bool→BIGINT round-trip.
    let bound = store
        .persist_result(|tx| {
            tx.bind_paper_book_ocr_conversion_execution_artifacts_to_dossier(
                &import_id,
                &draft_id,
                &dossier_id,
            )
        })
        .unwrap();
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].dossier_id.as_deref(), Some(dossier_id.as_str()));
    assert!(!bound[0].legal_validity_claimed);
    assert!(bound[0].mutable_draft_act_created);

    // --- Paged ledger read (newest-first) over persisted events ---
    let mut ledger = Ledger::new();
    for i in 0..3 {
        let event = ledger
            .append(
                "amelia.marques",
                "application",
                &format!("app.event.{i}"),
                None,
                format!("payload-{i}").as_bytes(),
            )
            .clone();
        store.persist(|tx| tx.append_event(&event)).unwrap();
    }
    let page = store
        .ledger_events_page(&LedgerEventPageQuery {
            before_seq: None,
            limit: 2,
            chain: None,
            q: None,
            scope: None,
            kinds: Vec::new(),
            actor: None,
            from: None,
            to: None,
        })
        .unwrap();
    assert_eq!(page.events.len(), 2, "page clamps to the requested limit");
    assert!(page.has_more, "a third event remains");
    assert!(
        page.events[0].seq > page.events[1].seq,
        "events return newest-first"
    );
}
