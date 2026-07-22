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

use std::path::{Path, PathBuf};

use chancela_core::{
    ActId, CompanyGroup, GroupTemplateLibrary, GroupTemplateLibraryRevision, TenantId,
};
use chancela_ledger::Ledger;
use chancela_store::recovery::ResetScope;
use chancela_store::{
    EraseTarget, LedgerEventPageQuery, PendingCmdSession, Store, StoreBackendSelection, StoreError,
    StoredDocument, StoredFollowUp, StoredFollowUpStatus, StoredGeneratedDocumentDispatchEvidence,
    StoredImportedDocument, StoredImportedDocumentMeta, StoredImportedDocumentReviewStatus,
    StoredPaperBookImport, StoredPaperBookImportMeta, StoredPaperBookOcrConversionDossier,
    StoredPaperBookOcrConversionExecutionArtifact, StoredPaperBookOcrDraft,
    StoredPaperBookOcrPageSpan, StoredPaperBookOcrReviewStatus, StoredPaperBookOcrStatus,
    StoredSignedDocument,
};
use postgres::NoTls;
use time::OffsetDateTime;

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty())
}

struct IsolatedPostgresDb {
    admin_config: postgres::Config,
    database_name: String,
    database_url: String,
}

impl IsolatedPostgresDb {
    fn create(parent_url: &str, tag: &str) -> Result<Self, postgres::Error> {
        let admin_config: postgres::Config = parent_url.parse()?;
        let parent_name = admin_config
            .get_dbname()
            .or_else(|| admin_config.get_user())
            .unwrap_or("chancela");
        let database_name = isolated_database_name(parent_name, tag);

        let mut admin = admin_config.connect(NoTls)?;
        admin.batch_execute(&format!("CREATE DATABASE {}", quote_ident(&database_name)))?;

        let mut child_config = admin_config.clone();
        child_config.dbname(&database_name);
        let database_url = libpq_connection_string(&child_config);

        Ok(Self {
            admin_config,
            database_name,
            database_url,
        })
    }

    fn url(&self) -> String {
        self.database_url.clone()
    }
}

impl Drop for IsolatedPostgresDb {
    fn drop(&mut self) {
        let mut admin = match self.admin_config.connect(NoTls) {
            Ok(admin) => admin,
            Err(err) => {
                eprintln!(
                    "failed to connect for cleanup of postgres test database {}: {err}",
                    self.database_name
                );
                return;
            }
        };
        if let Err(err) = admin.batch_execute(&format!(
            "DROP DATABASE IF EXISTS {}",
            quote_ident(&self.database_name)
        )) {
            eprintln!(
                "failed to drop postgres test database {}: {err}",
                self.database_name
            );
        }
    }
}

fn isolated_postgres(tag: &str) -> Option<IsolatedPostgresDb> {
    let Some(database_url) = database_url() else {
        eprintln!("skipping: DATABASE_URL not set");
        return None;
    };
    Some(IsolatedPostgresDb::create(&database_url, tag).expect("create isolated postgres database"))
}

fn isolated_database_name(parent: &str, tag: &str) -> String {
    let parent = sanitize_ident_part(parent);
    let tag = sanitize_ident_part(tag);
    let tag = &tag[..tag.len().min(24)];
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let suffix = format!("_{tag}_{}", &unique[..12]);
    let max_parent_len = 63usize.saturating_sub(suffix.len());
    format!("{}{}", &parent[..parent.len().min(max_parent_len)], suffix)
}

fn sanitize_ident_part(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.starts_with(|ch: char| ch.is_ascii_digit()) {
        out.insert_str(0, "chancela");
    }
    out
}

fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn libpq_connection_string(config: &postgres::Config) -> String {
    let mut parts = Vec::new();
    if let Some(user) = config.get_user() {
        parts.push(libpq_kv("user", user));
    }
    if let Some(password) = config.get_password() {
        parts.push(libpq_kv(
            "password",
            String::from_utf8_lossy(password).as_ref(),
        ));
    }
    if let Some(dbname) = config.get_dbname() {
        parts.push(libpq_kv("dbname", dbname));
    }
    if !config.get_hosts().is_empty() {
        let hosts = config
            .get_hosts()
            .iter()
            .map(|host| match host {
                postgres::config::Host::Tcp(host) => host.clone(),
                #[cfg(unix)]
                postgres::config::Host::Unix(path) => path.to_string_lossy().into_owned(),
            })
            .collect::<Vec<_>>()
            .join(",");
        parts.push(libpq_kv("host", &hosts));
    }
    if !config.get_hostaddrs().is_empty() {
        let hostaddrs = config
            .get_hostaddrs()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        parts.push(libpq_kv("hostaddr", &hostaddrs));
    }
    if !config.get_ports().is_empty() {
        let ports = config
            .get_ports()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        parts.push(libpq_kv("port", &ports));
    }
    if let Some(options) = config.get_options() {
        parts.push(libpq_kv("options", options));
    }
    if let Some(application_name) = config.get_application_name() {
        parts.push(libpq_kv("application_name", application_name));
    }
    if let Some(timeout) = config.get_connect_timeout() {
        parts.push(libpq_kv("connect_timeout", &timeout.as_secs().to_string()));
    }
    parts.join(" ")
}

fn libpq_kv(key: &str, value: &str) -> String {
    format!(
        "{key}='{}'",
        value.replace('\\', "\\\\").replace('\'', "\\'")
    )
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
    let Some(isolated) = isolated_postgres("persist-reload") else {
        return;
    };
    let database_url = isolated.url();
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

/// The group graph uses the same document-in-relational contract on Postgres as SQLite, including
/// immutable composite-key revisions and aggregate-snapshot reloads.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn company_groups_and_template_library_revisions_roundtrip_on_postgres() {
    let Some(isolated) = isolated_postgres("group-roundtrip") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres {
        database_url: database_url.clone(),
    })
    .expect("open postgres backend");
    let tenant_id = TenantId::new();
    let group = CompanyGroup::new(tenant_id, "Grupo Encosto", OffsetDateTime::UNIX_EPOCH);
    let library = GroupTemplateLibrary::new(&group, "Atas", OffsetDateTime::UNIX_EPOCH);
    let revision = GroupTemplateLibraryRevision {
        group_id: group.id,
        library_id: library.id,
        tenant_id,
        revision: 1,
        template_ids: vec!["csc-ata-ag/v1".to_owned()],
        created_at: OffsetDateTime::UNIX_EPOCH,
        created_by: "postgres-test".to_owned(),
    };
    store
        .persist(|tx| {
            tx.upsert_company_group(&group)?;
            tx.upsert_group_template_library(&library)?;
            tx.insert_group_template_library_revision(&revision)
        })
        .expect("persist group graph");
    assert!(
        store
            .persist(|tx| tx.insert_group_template_library_revision(&revision))
            .is_err(),
        "the composite key refuses rewriting revision one"
    );
    let snapshot = store
        .cluster_load_aggregates()
        .expect("load group snapshot");
    assert_eq!(snapshot.company_groups.get(&group.id), Some(&group));
    assert_eq!(
        snapshot.group_template_libraries.get(&library.id),
        Some(&library)
    );
    assert_eq!(snapshot.group_template_library_revisions.len(), 1);
    drop(store);

    let reopened = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("reopen postgres backend");
    let loaded = reopened.load().expect("reload group graph");
    assert_eq!(loaded.company_groups.get(&group.id), Some(&group));
    assert_eq!(
        loaded
            .group_template_library_revisions
            .get(&(group.id, library.id, 1)),
        Some(&revision)
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
    let Some(isolated) = isolated_postgres("runtime-roundtrip") else {
        return;
    };
    let database_url = isolated.url();
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
        template_spec_json: None,
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
            technical_validation_report_json: "{}".to_owned(),
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

// =================================================================================================
// wp15 — logical backup / restore / recovery for the Postgres backend
// =================================================================================================

/// A unique scratch directory for a backup archive (the bundle file lives on the local host even
/// though the durability sink is Postgres).
fn unique_data_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chancela-wp15-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn sample_document(act_id: ActId, tag: &str) -> StoredDocument {
    StoredDocument {
        id: format!("doc-{tag}-{}", uuid::Uuid::new_v4()),
        act_id,
        template_id: "csc-ata-ag/v1".to_string(),
        pdf_digest: format!("{tag:0>8}"),
        profile: "csc/sq".to_string(),
        created_at: ts(1_770_000_000),
        pdf_bytes: format!("%PDF-1.7 {tag}").into_bytes(),
        template_spec_json: None,
    }
}

/// Seed a blank, coherent instance: factory-reset to clear any residue, then append `events` and a
/// generated document so there is real, checkable data to back up.
fn seed_blank_instance(store: &Store, data_dir: &Path) -> (Ledger, ActId) {
    let mut ledger = store.load().expect("load").ledger;
    store
        .reset(
            &mut ledger,
            data_dir,
            ResetScope::BackendFactory,
            false,
            &[],
            "amelia.marques",
            ts(1_700_000_000),
        )
        .expect("factory reset to blank");
    assert_eq!(ledger.len(), 0, "factory reset blanks the ledger");
    (ledger, ActId(uuid::Uuid::new_v4()))
}

/// Round-trip: a logical backup captured mid-history restores every table + the ledger head exactly,
/// reverting any writes made after the snapshot (the restored chain re-verifies, and the appended
/// `ledger.restored` is the only addition beyond the snapshot length).
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn logical_backup_restore_roundtrips_on_postgres() {
    let Some(isolated) = isolated_postgres("logical-backup-restore") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("roundtrip");
    let (mut ledger, act_a) = seed_blank_instance(&store, &data_dir);

    // Seed a couple of events + a document under act A.
    for i in 0..2 {
        let ev = ledger
            .append(
                "amelia.marques",
                "application",
                &format!("app.seed.{i}"),
                None,
                b"x",
            )
            .clone();
        store.persist(|tx| tx.append_event(&ev)).unwrap();
    }
    let doc_a = sample_document(act_a, "a");
    store.persist(|tx| tx.upsert_document(&doc_a)).unwrap();
    let head_at_backup = ledger.head().map(|h| lower_hex(&h));
    let len_at_backup = ledger.len() as u64;

    // Backup captures this point-in-time.
    let manifest = store.backup(&data_dir, &[]).expect("logical backup");
    assert_eq!(
        manifest.ledger_head, head_at_backup,
        "manifest head == live head"
    );
    assert_eq!(manifest.ledger_length, len_at_backup);
    assert!(manifest.ledger_verified, "snapshot chain verified");

    // Mutate PAST the backup: another event + a document under act B.
    let ev = ledger
        .append(
            "amelia.marques",
            "application",
            "app.after.backup",
            None,
            b"y",
        )
        .clone();
    store.persist(|tx| tx.append_event(&ev)).unwrap();
    let act_b = ActId(uuid::Uuid::new_v4());
    let doc_b = sample_document(act_b, "b");
    store.persist(|tx| tx.upsert_document(&doc_b)).unwrap();
    assert!(store.document_for_act(act_b).unwrap().is_some());

    // Restore reverts to the snapshot (all-or-nothing).
    let mut restored_ledger = ledger.clone();
    let outcome = store
        .restore(
            &mut restored_ledger,
            Path::new(&manifest.path),
            &data_dir,
            "amelia.marques",
            ts(1_800_000_000),
        )
        .expect("restore");
    assert!(outcome.chain_verified);
    assert_eq!(
        outcome.ledger_length,
        len_at_backup + 1,
        "restored length = snapshot + the appended ledger.restored"
    );

    // Document A is back exactly; document B (post-backup) is gone; the reloaded chain verifies.
    assert_eq!(
        store.document_for_act(act_a).unwrap().as_ref(),
        Some(&doc_a)
    );
    assert!(store.document_for_act(act_b).unwrap().is_none());
    let loaded = store.load().unwrap();
    assert!(loaded.chain_status.is_ok(), "restored chain re-verifies");

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Domain-wipe preserves + audits the ledger; whole-instance start-over reinitializes a fresh
/// single-event chain; factory-blank clears everything to a coherent empty instance whose meta
/// (`instance_id`) still resolves.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn wipe_start_over_and_factory_reset_stay_coherent_on_postgres() {
    let Some(isolated) = isolated_postgres("recovery") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("recovery");
    let (mut ledger, act) = seed_blank_instance(&store, &data_dir);
    let doc = sample_document(act, "seed");
    store.persist(|tx| tx.upsert_document(&doc)).unwrap();

    // Domain wipe: document cleared, ledger PRESERVED and grows a chained data.wiped, chain verifies.
    let len_before_wipe = ledger.len();
    store
        .reset(
            &mut ledger,
            &data_dir,
            ResetScope::BackendDomain,
            false,
            &[],
            "amelia.marques",
            ts(1_700_000_100),
        )
        .expect("domain wipe");
    assert!(
        store.document_for_act(act).unwrap().is_none(),
        "domain data cleared"
    );
    assert!(
        ledger.len() > len_before_wipe,
        "data.wiped appended to the preserved ledger"
    );
    assert!(
        store.load().unwrap().chain_status.is_ok(),
        "post-wipe chain verifies"
    );

    // Whole-instance start-over: fresh ledger whose genesis is ledger.reinitialized.
    store
        .start_over_instance(
            &mut ledger,
            "clean slate",
            "amelia.marques",
            ts(1_700_000_200),
            &data_dir,
            &[],
        )
        .expect("start over instance");
    let after = store.load().unwrap();
    assert_eq!(
        after.ledger.len(),
        1,
        "start-over seeds a single genesis event"
    );
    assert!(after.chain_status.is_ok(), "reinitialized chain verifies");

    // Factory blank: everything gone, but the instance meta still resolves.
    store
        .reset(
            &mut ledger,
            &data_dir,
            ResetScope::BackendFactory,
            false,
            &[],
            "amelia.marques",
            ts(1_700_000_300),
        )
        .expect("factory reset");
    let blank = store.load().unwrap();
    assert_eq!(blank.ledger.len(), 0);
    assert!(blank.entities.is_empty() && blank.books.is_empty() && blank.acts.is_empty());
    assert!(
        !store.instance_id().unwrap().is_empty(),
        "instance_id survives a factory blank"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A corrupted bundle is rejected by restore BEFORE any table is touched, so the live database is
/// left exactly as it was (verify-before-trust; no partial apply).
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn restore_rejects_a_corrupt_bundle_and_leaves_the_database_unchanged() {
    let Some(isolated) = isolated_postgres("corrupt-restore") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("corrupt");
    let (ledger, act_a) = seed_blank_instance(&store, &data_dir);
    let doc_a = sample_document(act_a, "a");
    store.persist(|tx| tx.upsert_document(&doc_a)).unwrap();

    let manifest = store.backup(&data_dir, &[]).expect("logical backup");

    // A distinguishing post-backup write that a partial/successful restore would remove.
    let act_b = ActId(uuid::Uuid::new_v4());
    let doc_b = sample_document(act_b, "b");
    store.persist(|tx| tx.upsert_document(&doc_b)).unwrap();

    // Corrupt a table member without updating the manifest/table digest.
    let bytes = std::fs::read(&manifest.path).unwrap();
    let corrupt_path = data_dir.join("corrupt-bundle.zip");
    std::fs::write(
        &corrupt_path,
        corrupt_zip_member(&bytes, "tables/documents.jsonl"),
    )
    .unwrap();

    let mut restore_ledger = ledger.clone();
    let err = store
        .restore(
            &mut restore_ledger,
            &corrupt_path,
            &data_dir,
            "amelia.marques",
            ts(1_800_000_000),
        )
        .expect_err("corrupt bundle must be refused");
    assert!(matches!(err, StoreError::BadBackup(_)), "{err:?}");

    // Untouched: BOTH documents still present (the restore never ran).
    assert!(store.document_for_act(act_a).unwrap().is_some());
    assert!(store.document_for_act(act_b).unwrap().is_some());

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Cross-backend: a genuine SQLite file-swap bundle is refused by the Postgres logical restore with
/// a clear, named error (the two bundle shapes are deliberately not interchangeable).
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn postgres_restore_rejects_a_sqlite_bundle() {
    let Some(isolated) = isolated_postgres("sqlite-reject") else {
        return;
    };
    let database_url = isolated.url();
    // Produce a real SQLite backup.
    let sqlite_dir = unique_data_dir("sqlite-src");
    let sqlite_manifest = {
        let sqlite = Store::open(&sqlite_dir).expect("open sqlite");
        let mut sl = sqlite.load().unwrap().ledger;
        let ev = sl
            .append("amelia.marques", "application", "app.started", None, b"z")
            .clone();
        sqlite.persist(|tx| tx.append_event(&ev)).unwrap();
        sqlite.backup(&sqlite_dir, &[]).expect("sqlite backup")
    };

    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let pg_dir = unique_data_dir("pg-dst");
    let mut ledger = store.load().unwrap().ledger;
    let err = store
        .restore(
            &mut ledger,
            Path::new(&sqlite_manifest.path),
            &pg_dir,
            "amelia.marques",
            ts(1_800_000_000),
        )
        .expect_err("a sqlite bundle must be refused by the postgres restore");
    assert!(
        matches!(err, StoreError::BadBackup(ref m) if m.contains("postgres logical backup manifest")),
        "{err:?}"
    );

    let _ = std::fs::remove_dir_all(&sqlite_dir);
    let _ = std::fs::remove_dir_all(&pg_dir);
}

/// Lowercase-hex helper (the crate's internal `hex` is not exported).
fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// =================================================================================================
// wp21 — per-book export / import / start-over + restore-preflight on the Postgres backend
// =================================================================================================

use chancela_core::{Act, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc};
use chancela_store::recovery::{CollisionPolicy, ImportVerdict, StartOverScope};

fn sample_entity() -> Entity {
    Entity::new(
        "Encosto Estrategico Lda",
        Nipc::unvalidated("500002020"),
        "Rua de Teste, Lisboa",
        EntityKind::SociedadePorQuotas,
    )
}

/// Seed a blank instance with one entity + one book carrying a valid book chain (`book.opened`
/// genesis + one `act.sealed`), an act, and a generated document. Mirrors the SQLite recovery-test
/// `seed`, so the per-book bundle it produces is byte-shaped identically across backends.
fn seed_book(store: &Store, data_dir: &Path) -> (Ledger, Entity, Book, Act) {
    let (mut ledger, _) = seed_blank_instance(store, data_dir);
    let entity = sample_entity();
    let book = Book::new(entity.id, BookKind::AssembleiaGeral);
    let act = Act::draft(book.id, "Ata n.o 1", MeetingChannel::Physical);
    let doc = sample_document(act.id, "book-seed");

    let scope_entity = format!("entity:{}", entity.id);
    let scope_book = format!("entity:{}/book:{}", entity.id, book.id);

    let e0 = ledger
        .append(
            "amelia.marques",
            &scope_entity,
            "entity.created",
            None,
            b"e",
        )
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e0)?;
            tx.upsert_entity(&entity)
        })
        .unwrap();

    let e1 = ledger
        .append("amelia.marques", &scope_book, "book.opened", None, b"open")
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e1)?;
            tx.upsert_book(&book)
        })
        .unwrap();

    let e2 = ledger
        .append("amelia.marques", &scope_book, "act.sealed", None, b"seal")
        .clone();
    store
        .persist(|tx| {
            tx.append_event(&e2)?;
            tx.upsert_act(&act)?;
            tx.upsert_document(&doc)
        })
        .unwrap();

    (ledger, entity, book, act)
}

/// Read one member's bytes out of a zip archive.
fn zip_member(archive_bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes)).ok()?;
    let mut f = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf).ok()?;
    Some(buf)
}

fn corrupt_zip_member(archive_bytes: &[u8], member_name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archive_bytes)).unwrap();
    let mut members = Vec::new();
    let mut found = false;
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let name = f.name().to_owned();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut bytes).unwrap();
        if name == member_name {
            found = true;
            if bytes.is_empty() {
                bytes.push(b'!');
            } else {
                bytes[0] ^= 0xFF;
            }
        }
        members.push((name, bytes));
    }
    assert!(found, "zip member {member_name} should exist");

    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in members {
        zip.start_file(name, opts).unwrap();
        std::io::Write::write_all(&mut zip, &bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// Per-book export → import round-trip on Postgres: the logical bundle carries the book + entity +
/// acts + the book-chain events; re-importing (after a factory blank clears the original) verifies
/// clean, records the isolated import + retained bundle, and never merges the foreign chain onto the
/// live spine.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn per_book_export_import_roundtrips_on_postgres() {
    let Some(isolated) = isolated_postgres("perbook-roundtrip") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("perbook-roundtrip");
    let (mut ledger, entity, book, act) = seed_book(&store, &data_dir);

    // Export the book to a self-verifying bundle.
    let export = store
        .export_book(
            &mut ledger,
            book.id,
            &data_dir,
            "amelia.marques",
            ts(1_800_000_000),
        )
        .expect("export book on postgres");
    assert!(export.path.exists(), "bundle retained under exports/");
    assert_eq!(export.manifest.book_id, book.id.to_string());
    assert_eq!(export.manifest.entity_id, entity.id.to_string());
    assert!(export.manifest.book_chain.verified, "book chain verified");
    assert_eq!(
        export.manifest.book_chain.length, 2,
        "book.opened + act.sealed"
    );
    assert!(
        ledger.events().iter().any(|e| e.kind == "ledger.exported"),
        "a chained ledger.exported was appended"
    );
    // The bundle really carries the act + a coherent events.jsonl.
    let events_jsonl = zip_member(&export.bytes, "events.jsonl").expect("events.jsonl present");
    assert_eq!(
        events_jsonl.iter().filter(|b| **b == b'\n').count(),
        2,
        "two book-chain events serialized"
    );
    assert!(
        zip_member(&export.bytes, &format!("acts/{}.json", act.id)).is_some(),
        "the act member is present"
    );

    // Factory-blank clears the live book, then re-import → Verified, isolated, no collision.
    let mut dst_ledger = store.load().unwrap().ledger;
    store
        .reset(
            &mut dst_ledger,
            &data_dir,
            ResetScope::BackendFactory,
            false,
            &[],
            "amelia.marques",
            ts(1_800_000_100),
        )
        .expect("factory blank before re-import");

    let outcome = store
        .import_book(
            &mut dst_ledger,
            &export.path,
            CollisionPolicy::Refuse,
            "amelia.marques",
            ts(1_800_000_200),
        )
        .expect("import book on postgres");
    assert!(
        matches!(outcome.verdict, ImportVerdict::Verified),
        "{outcome:?}"
    );
    assert_eq!(outcome.book_id, book.id.to_string());
    assert!(!outcome.collided);
    assert_eq!(
        outcome.source_instance_id,
        export.manifest.source_instance_id
    );

    // Isolated: the live spine holds only the chained ledger.imported, NOT the foreign book chain.
    assert!(
        dst_ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.imported"),
        "ledger.imported recorded"
    );
    assert_eq!(
        store.load().unwrap().books.len(),
        0,
        "the imported book is not merged into live books"
    );

    // The import registry + retained bundle are queryable and byte-exact.
    let imported = store.imported_books().expect("imported_books feed");
    assert_eq!(imported.len(), 1);
    assert_eq!(imported[0].book_id, book.id.to_string());
    assert!(matches!(imported[0].verdict, ImportVerdict::Verified));
    let retained = store
        .imported_bundle(&outcome.import_id)
        .expect("imported_bundle")
        .expect("bundle bytes retained");
    assert_eq!(retained, export.bytes, "retained bundle is byte-identical");

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// A tampered bundle is quarantined (never trusted as Verified), and a colliding import under the
/// default `Refuse` policy errors and leaves the DB untouched (atomic: no imported_books row, no
/// ledger.imported event).
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn per_book_import_quarantines_tamper_and_refuses_collision_atomically_on_postgres() {
    let Some(isolated) = isolated_postgres("perbook-tamper") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("perbook-tamper");
    let (mut ledger, _entity, book, _act) = seed_book(&store, &data_dir);
    let export = store
        .export_book(
            &mut ledger,
            book.id,
            &data_dir,
            "amelia.marques",
            ts(1_800_000_000),
        )
        .expect("export book");

    // --- Tamper: flip a byte inside the events.jsonl member so the book chain no longer verifies. ---
    let bundle = std::fs::read(&export.path).unwrap();
    let (manifest, mut members) = {
        let mut m: Option<serde_json::Value> = None;
        let mut map = std::collections::HashMap::new();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bundle)).unwrap();
        for i in 0..zip.len() {
            let mut f = zip.by_index(i).unwrap();
            let name = f.name().to_owned();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut buf).unwrap();
            if name == "manifest.json" {
                m = Some(serde_json::from_slice(&buf).unwrap());
            } else {
                map.insert(name, buf);
            }
        }
        (m.unwrap(), map)
    };
    // Corrupt a member WITHOUT updating its manifest digest → member-digest mismatch → quarantined.
    if let Some(ev) = members.get_mut("events.jsonl")
        && let Some(b) = ev.first_mut()
    {
        *b ^= 0xFF;
    }
    let tampered_path = data_dir.join("tampered.zip");
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.json", opts).unwrap();
        std::io::Write::write_all(&mut zip, &serde_json::to_vec(&manifest).unwrap()).unwrap();
        for (name, bytes) in &members {
            zip.start_file(name.as_str(), opts).unwrap();
            std::io::Write::write_all(&mut zip, bytes).unwrap();
        }
        std::fs::write(&tampered_path, zip.finish().unwrap().into_inner()).unwrap();
    }
    // manifest is left intact on purpose (only member bytes were flipped ⇒ a member-digest mismatch).

    let mut dst_ledger = store.load().unwrap().ledger;
    let tamper_outcome = store
        .import_book(
            &mut dst_ledger,
            &tampered_path,
            CollisionPolicy::QuarantineCopy,
            "amelia.marques",
            ts(1_800_000_300),
        )
        .expect("a tampered bundle is recorded, not errored");
    assert!(
        matches!(tamper_outcome.verdict, ImportVerdict::Quarantined { .. }),
        "tampered bundle must quarantine, never Verified: {tamper_outcome:?}"
    );

    // --- Collision + Refuse: the book already exists (imported above), so Refuse errors atomically. ---
    let before = store.imported_books().unwrap().len();
    let ledger_len_before = store.load().unwrap().ledger.len();
    let mut dst_ledger2 = store.load().unwrap().ledger;
    let err = store
        .import_book(
            &mut dst_ledger2,
            &export.path,
            CollisionPolicy::Refuse,
            "amelia.marques",
            ts(1_800_000_400),
        )
        .expect_err("a colliding Refuse import must error");
    assert!(matches!(err, StoreError::ImportCollision { .. }), "{err:?}");
    assert_eq!(
        store.imported_books().unwrap().len(),
        before,
        "no imported_books row was written on the refused collision"
    );
    assert_eq!(
        store.load().unwrap().ledger.len(),
        ledger_len_before,
        "no ledger.imported event was written on the refused collision (atomic no-op)"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Per-book start-over on Postgres: archives the current book (chained `ledger.exported`), appends a
/// chained `ledger.reinitialized`, and persists a fresh successor book shell — all in coherent PG
/// transactions. The old book survives (append-only) and the successor exists in `Created` state.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn per_book_start_over_stays_coherent_on_postgres() {
    let Some(isolated) = isolated_postgres("perbook-startover") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("perbook-startover");
    let (mut ledger, _entity, book, _act) = seed_book(&store, &data_dir);
    let len_before = ledger.len();

    let outcome = store
        .start_over_book(
            &mut ledger,
            book.id,
            "recomecar o livro",
            "amelia.marques",
            ts(1_800_000_000),
            &data_dir,
        )
        .expect("start over book on postgres");
    assert!(matches!(outcome.scope, StartOverScope::Book));
    assert_eq!(outcome.old_book_id, Some(book.id.to_string()));
    let new_book_id = outcome.new_book_id.expect("successor book id");
    assert_ne!(new_book_id, book.id.to_string());

    // The ledger grew a chained ledger.exported + ledger.reinitialized and still verifies.
    assert!(ledger.events().iter().any(|e| e.kind == "ledger.exported"));
    assert!(
        ledger
            .events()
            .iter()
            .any(|e| e.kind == "ledger.reinitialized")
    );
    assert!(ledger.len() >= len_before + 2, "export + reinit appended");

    let loaded = store.load().unwrap();
    assert!(
        loaded.chain_status.is_ok(),
        "post start-over chain verifies"
    );
    // Both the old book and the fresh successor shell are present.
    assert!(
        loaded.books.contains_key(&book.id),
        "old book preserved (append-only)"
    );
    assert!(
        loaded.books.keys().any(|k| k.to_string() == new_book_id),
        "successor book shell persisted"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// The Postgres restore-preflight is a full in-memory verify-before-trust of the logical bundle:
/// it proves restorability (ok/ready) without touching the live database, and refuses a corrupted
/// bundle with bounded errors — again leaving the live DB untouched.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn restore_preflight_is_non_destructive_and_rejects_a_bad_bundle_on_postgres() {
    let Some(isolated) = isolated_postgres("preflight") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");
    let data_dir = unique_data_dir("preflight");
    let (_ledger, _entity, _book, act) = seed_book(&store, &data_dir);

    // A whole-store logical backup to preflight.
    let manifest = store.backup(&data_dir, &[]).expect("logical backup");

    // A distinguishing live row a destructive preflight would disturb.
    let sentinel = sample_document(ActId(uuid::Uuid::new_v4()), "sentinel");
    store.persist(|tx| tx.upsert_document(&sentinel)).unwrap();

    // Good bundle → ok/ready, no temp-dir drill (in-memory verify), and the live sentinel survives.
    let good = store
        .restore_preflight(Path::new(&manifest.path), &data_dir, None)
        .expect("preflight good bundle");
    assert!(good.ok && good.ready, "good bundle is restorable: {good:?}");
    assert!(good.ledger_verified, "ledger re-verified in memory");
    assert!(
        good.isolated_restore.is_none(),
        "postgres preflight uses the in-memory verify, not a temp-file drill"
    );
    assert!(
        store.document_by_id(&sentinel.id).unwrap().is_some(),
        "live database untouched by the good-bundle preflight"
    );
    // The seeded act is still live too.
    assert!(store.document_for_act(act.id).unwrap().is_some());

    // Corrupt a table member without updating the manifest/table digest.
    let bytes = std::fs::read(&manifest.path).unwrap();
    let corrupt_path = data_dir.join("corrupt-backup.zip");
    std::fs::write(
        &corrupt_path,
        corrupt_zip_member(&bytes, "tables/documents.jsonl"),
    )
    .unwrap();
    let bad = store
        .restore_preflight(&corrupt_path, &data_dir, None)
        .expect("preflight bad bundle returns evidence, not an error");
    assert!(!bad.ok && !bad.ready, "corrupt bundle is not restorable");
    assert!(!bad.errors.is_empty(), "bounded errors surfaced");
    assert!(
        store.document_by_id(&sentinel.id).unwrap().is_some(),
        "live database untouched by the bad-bundle preflight"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Opening with an explicit `sslmode=verify-full` drives the connection through the rustls TLS
/// connector ([`chancela_store::pg_tls`]) instead of `NoTls`. The server must present a certificate
/// chaining to `CHANCELA_PG_TLS_ROOT_CERT` (or an OS root) whose SAN matches the DSN host. This proves
/// the rustls `MakeTlsConnect` integrates with the synchronous `postgres` + r2d2 stack (pool +
/// writer), and that the explicit URL mode is stripped, resolved, and enforced without falling back
/// to an unauthenticated or plaintext connection.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn sslmode_verify_full_opens_and_roundtrips_on_postgres() {
    let Some(isolated) = isolated_postgres("sslmode-verify-full") else {
        return;
    };
    // The isolated URL is libpq keyword form; append an explicit sslmode the resolver must honor.
    let database_url = format!("{} sslmode=verify-full", isolated.url());
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend with sslmode=verify-full");

    let mut ledger = Ledger::new();
    let event = ledger
        .append(
            "amelia.marques",
            "application",
            "app.started",
            None,
            b"postgres-tls-verify-full",
        )
        .clone();
    store
        .persist(|tx| tx.append_event(&event))
        .expect("persist over the resolved verified-TLS connection");

    let loaded = store.load().expect("reload over the resolved connection");
    assert_eq!(
        loaded.ledger.len(),
        1,
        "one event replays over the TLS-capable connector"
    );
    assert!(
        loaded.chain_status.is_ok(),
        "replayed chain verifies over the verified-TLS connection"
    );
}

/// wp26 — the per-subject GDPR erasure primitives on Postgres: `subject_keys` roundtrip +
/// crypto-erase (BYTEA `wrapped_dek` emptied, `erased_at` stamped), a multi-collection
/// `erase_subject`, the unknown-collection SQL-injection guard, and `VACUUM (FULL, ANALYZE)`.
/// SQLite parity lives in `store.rs`; this proves the Postgres arms behave identically.
#[test]
#[ignore = "requires a live PostgreSQL at DATABASE_URL"]
fn subject_erasure_primitives_roundtrip_on_postgres() {
    let Some(isolated) = isolated_postgres("subject-erasure") else {
        return;
    };
    let database_url = isolated.url();
    let store = Store::open_backend(StoreBackendSelection::Postgres { database_url })
        .expect("open postgres backend");

    let subject_id = "8f3b1e2a-0c4d-4e6f-9a1b-2c3d4e5f6a7b";
    assert!(store.get_subject_key(subject_id).unwrap().is_none());

    // subject_keys roundtrip + crypto-erase.
    let wrapped_dek: Vec<u8> = vec![0x00, 0xFF, 0xFE, 0x10, 0x80, 0x81, 0x7F];
    store
        .persist(|tx| tx.put_subject_key(subject_id, &wrapped_dek, 1, "2026-07-15T09:00:00Z"))
        .expect("put subject key");
    let live = store
        .get_subject_key(subject_id)
        .unwrap()
        .expect("row present");
    assert_eq!(live.wrapped_dek, wrapped_dek);
    assert_eq!(live.erased_at, None);
    store
        .persist(|tx| tx.destroy_subject_key(subject_id, "2026-07-15T10:00:00Z"))
        .expect("destroy subject key");
    let erased = store.get_subject_key(subject_id).unwrap().unwrap();
    assert!(
        erased.wrapped_dek.is_empty(),
        "wrapped DEK emptied on erase"
    );
    assert_eq!(erased.erased_at.as_deref(), Some("2026-07-15T10:00:00Z"));

    // Multi-collection erase across id-keyed sidecar tables.
    store
        .persist(|tx| {
            tx.upsert_user("u-amelia", r#"{"username":"amelia.marques"}"#)?;
            tx.upsert_role("r-amelia", r#"{"holder":"amelia.marques"}"#)?;
            tx.upsert_user("u-rui", r#"{"username":"rui.secretario"}"#)?;
            Ok(())
        })
        .expect("seed subject rows");
    let targets = vec![
        EraseTarget {
            collection: "users".to_owned(),
            id: "u-amelia".to_owned(),
        },
        EraseTarget {
            collection: "roles".to_owned(),
            id: "r-amelia".to_owned(),
        },
        EraseTarget {
            collection: "follow_ups".to_owned(),
            id: "fu-absent".to_owned(),
        },
    ];
    let report = store
        .erase_subject("amelia.marques", &targets)
        .expect("erase subject");
    assert_eq!(report.outcomes[0].deleted, 1);
    assert_eq!(report.outcomes[1].deleted, 1);
    assert_eq!(report.outcomes[2].deleted, 0, "absent id is a no-op");
    assert!(store.users().unwrap().iter().any(|(id, _)| id == "u-rui"));
    assert!(store.roles().unwrap().is_empty());

    // Unknown-collection guard rolls the whole transaction back.
    let bad = vec![
        EraseTarget {
            collection: "users".to_owned(),
            id: "u-rui".to_owned(),
        },
        EraseTarget {
            collection: "events; DROP TABLE users --".to_owned(),
            id: "x".to_owned(),
        },
    ];
    assert!(matches!(
        store.erase_subject("amelia.marques", &bad).unwrap_err(),
        StoreError::UnknownErasableCollection { .. }
    ));
    assert!(
        store.users().unwrap().iter().any(|(id, _)| id == "u-rui"),
        "a rejected target must delete nothing"
    );

    // VACUUM (FULL, ANALYZE) runs Ok outside a transaction.
    store.vacuum().expect("vacuum on postgres");
}
