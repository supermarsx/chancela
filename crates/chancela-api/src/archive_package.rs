//! Internal preservation package export.
//!
//! `GET /v1/books/{id}/archive/package` builds a deterministic `application/zip` package from the
//! PDF/A documents and sidecar metadata already held by the API/store. This is deliberately named as
//! a Chancela internal preservation package, not a DGLAB-specific interchange format.

use std::collections::BTreeSet;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::Response;
use chancela_archive::{
    PackageBuildInput, PackageFileInput, PackageFileRole, PreservationLevel, ProducerMetadata,
    Provenance, ProvenanceSource, RetentionInstructions, RightsMetadata, build_archive_package,
    validate_package,
};
use chancela_authz::Permission;
use chancela_core::{Act, ActId, BookId, BookState, LegalHold};
use chancela_store::{StoredDocument, StoredSignedDocument};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::{require_permission, scope_of_book};
use crate::error::ApiError;

const PACKAGE_PROFILE: &str = "chancela-internal-preservation-package/v1";
const ZIP_CONTENT_TYPE: &str = "application/zip";
const JSON_CONTENT_TYPE: &str = "application/json";
const SIGNED_PDF_B_B_PROFILE: &str = "application/pdf; profile=PAdES-B-B";
const SIGNED_PDF_B_T_PROFILE: &str = "application/pdf; profile=PAdES-B-T";
const CERT_CONTENT_TYPE: &str = "application/pkix-cert";
const TIMESTAMP_TOKEN_CONTENT_TYPE: &str = "application/timestamp-reply";
const DSS_INSPECTION_INSPECTED: &str = "inspected_from_signed_pdf";
const DSS_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const PRODUCTION_B_LT_NOT_CLAIMED: &str = "not_claimed";
const DSS_BASIS: &str = "embedded_pdf_dss_catalog_inspection_only";

#[derive(Clone)]
struct PackageDocument {
    owner_kind: &'static str,
    owner_id: Uuid,
    act_id: Option<ActId>,
    document_id: Uuid,
    document: StoredDocument,
    signed: Option<StoredSignedDocument>,
}

struct BookArchiveInventory {
    entity_id: chancela_core::EntityId,
    entity_name: String,
    book_state: BookState,
    persisted_legal_hold: Option<LegalHold>,
    book_acts: Vec<Act>,
    package_docs: Vec<PackageDocument>,
}

#[derive(Debug, Deserialize)]
pub struct ExportArchivePackageQuery {
    #[serde(default)]
    legal_hold: bool,
    legal_hold_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DisposalSimulationRequest {
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalStatusView {
    book_id: Uuid,
    entity_id: Uuid,
    book_state: BookState,
    eligible: bool,
    blocked: bool,
    active_persisted_legal_hold: bool,
    export_time_legal_hold_persisted: bool,
    signed_evidence: SignedEvidenceSummary,
    reasons: Vec<DisposalReason>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedEvidenceSummary {
    present: bool,
    documents_total: usize,
    signed_documents: usize,
    unsigned_documents: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalReason {
    code: &'static str,
    blocking: bool,
    message: String,
}

#[derive(Debug, Serialize)]
pub struct DisposalSimulationView {
    dry_run: bool,
    status: DisposalStatusView,
    would_delete: WouldDeleteManifest,
}

#[derive(Debug, Serialize)]
pub struct WouldDeleteManifest {
    package_profile: &'static str,
    book_id: Uuid,
    entity_id: Uuid,
    book_state: BookState,
    source_records: Vec<WouldDeleteTarget>,
    package_members: Vec<WouldDeleteTarget>,
}

#[derive(Debug, Serialize)]
pub struct WouldDeleteTarget {
    kind: &'static str,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    act_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    document_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'static str>,
}

#[derive(Serialize)]
struct DocumentMetadataSidecar<'a> {
    package_profile: &'static str,
    owner: OwnerMetadata<'a>,
    document: DocumentMetadata<'a>,
    signed: Option<SignedMetadata<'a>>,
}

#[derive(Serialize)]
struct OwnerMetadata<'a> {
    kind: &'a str,
    id: Uuid,
    book_id: Uuid,
}

#[derive(Serialize)]
struct DocumentMetadata<'a> {
    id: Uuid,
    template_id: &'a str,
    profile: &'a str,
    created_at: String,
    pdf_digest: &'a str,
}

#[derive(Serialize)]
struct SignedMetadata<'a> {
    signed_pdf_digest: &'a str,
    signature_family: &'a str,
    evidentiary_level: &'a str,
    trusted_list_status: Option<&'a str>,
    signer_cert_subject: Option<&'a str>,
    signing_time: String,
    signed_at: String,
    signer_certificate_path: String,
    timestamp_token_path: Option<String>,
    signed_pdf_path: String,
}

#[derive(Serialize)]
struct ValidationEvidenceReport<'a> {
    package_profile: &'static str,
    report_kind: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    owner: OwnerMetadata<'a>,
    document_id: Uuid,
    act_id: Option<Uuid>,
    source: &'static str,
    archive_export_revalidated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<SignatureEvidence<'a>>,
}

#[derive(Serialize)]
struct SignatureEvidence<'a> {
    signed_pdf: SignedPdfEvidence<'a>,
    signature: SignatureMetadataEvidence<'a>,
    signer_certificate: SignerCertificateEvidence<'a>,
    timestamp_token: TimestampTokenEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_trust: Option<TimestampTrustEvidenceReport>,
    dss: DssEvidenceReport,
    persisted_validation: PersistedValidationEvidence,
}

#[derive(Serialize)]
struct SignedPdfEvidence<'a> {
    path: String,
    content_type: &'static str,
    sha256: &'a str,
}

#[derive(Serialize)]
struct SignatureMetadataEvidence<'a> {
    family: &'a str,
    evidentiary_level: &'a str,
    trusted_list_status: Option<&'a str>,
    signer_cert_subject: Option<&'a str>,
    signing_time: String,
    signed_at: String,
}

#[derive(Serialize)]
struct SignerCertificateEvidence<'a> {
    path: String,
    sha256: String,
    subject: Option<&'a str>,
}

#[derive(Serialize)]
struct TimestampTokenEvidence {
    present: bool,
    path: Option<String>,
    sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct TimestampTrustEvidenceReport {
    decision: String,
    policy_oid: String,
    policy_oid_accepted: Option<bool>,
    tsa_certificate_embedded: bool,
    embedded_certificate_count: usize,
    qtst_status: String,
    qtst_authenticated: bool,
    qtst_matches: Vec<TimestampQtstMatchEvidenceReport>,
    trust_anchor_count: usize,
    certificate_path_valid: bool,
    certificate_path_anchor_index: Option<usize>,
    certificate_path_len: Option<usize>,
    failure_reasons: Vec<String>,
    status_scope: String,
}

#[derive(Serialize, Deserialize)]
struct TimestampQtstMatchEvidenceReport {
    provider_name: String,
    service_name: String,
    granted_and_effective: bool,
    trust_anchor_count: usize,
}

#[derive(Serialize)]
struct DssEvidenceReport {
    basis: &'static str,
    present: bool,
    vri_count: usize,
    certificate_count: usize,
    ocsp_count: usize,
    crl_count: usize,
    certificate_sha256: Vec<String>,
    ocsp_sha256: Vec<String>,
    crl_sha256: Vec<String>,
    revocation_evidence_present: bool,
    local_b_lt_style_evidence_present: bool,
    live_revocation_fetching: bool,
    production_b_lt_status: &'static str,
    legal_b_lt_claimed: bool,
    inspection_status: &'static str,
}

#[derive(Serialize)]
struct PersistedValidationEvidence {
    basis: &'static str,
    byte_range_covers_whole_file_except_contents: &'static str,
    signer_certificate_matches_expected_certificate: &'static str,
    signature_timestamp: &'static str,
    timestamp_trust: &'static str,
    cryptographic_revalidation_at_export: &'static str,
}

#[derive(Serialize)]
struct LegalHoldEvidenceReport<'a> {
    package_profile: &'static str,
    report_kind: &'static str,
    status: &'static str,
    legal_hold: bool,
    reason: &'a str,
    scope: &'static str,
    persistence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set_at: Option<String>,
    created_at: String,
    book_id: Uuid,
}

struct PackageLegalHold {
    reason: String,
    persistence: &'static str,
    actor: Option<String>,
    set_at: Option<OffsetDateTime>,
}

/// `GET /v1/books/{id}/archive/disposal` - report whether archive disposal/destruction is
/// currently blocked. Export-time legal holds are deliberately package-local and never appear here.
pub async fn get_book_disposal_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<DisposalStatusView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(book_id),
    )
    .await?;

    let inventory = load_book_archive_inventory(&state, book_id).await?;
    Ok(Json(disposal_status(book_id, &inventory)))
}

/// `POST /v1/books/{id}/archive/disposal` - dry-run-only disposal simulation. This slice never
/// deletes data; `dry_run=false` is refused until a later destructive implementation exists.
pub async fn simulate_book_disposal(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<DisposalSimulationRequest>,
) -> Result<Json<DisposalSimulationView>, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(book_id),
    )
    .await?;

    if !req.dry_run {
        return Err(ApiError::Conflict(
            "destruição real ainda não está implementada; use dry_run=true".to_owned(),
        ));
    }

    let inventory = load_book_archive_inventory(&state, book_id).await?;
    let status = disposal_status(book_id, &inventory);
    if status.blocked {
        return Err(ApiError::Conflict(
            "disposição bloqueada por retenção/hold legal ativo ou ausência de documentos preservados"
                .to_owned(),
        ));
    }
    validate_archive_inventory(book_id, &inventory.package_docs)?;
    let would_delete = would_delete_manifest(book_id, &inventory);
    Ok(Json(DisposalSimulationView {
        dry_run: true,
        status,
        would_delete,
    }))
}

/// `GET /v1/books/{id}/archive/package` - stream a deterministic internal preservation ZIP for one
/// book. The endpoint is read-only: it does not append ledger events and does not retain the package.
pub async fn export_book_archive_package(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<ExportArchivePackageQuery>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    let book_id = BookId(id);
    require_permission(
        &state,
        &actor,
        Permission::BookExport,
        scope_of_book(book_id),
    )
    .await?;

    let BookArchiveInventory {
        entity_id,
        entity_name,
        persisted_legal_hold,
        book_acts,
        package_docs,
        ..
    } = load_book_archive_inventory(&state, book_id).await?;
    if package_docs.is_empty() {
        return Err(ApiError::Conflict(
            "o livro ainda não tem documentos PDF/A preservados para empacotar".to_owned(),
        ));
    }
    validate_archive_inventory(book_id, &package_docs)?;
    let legal_hold = package_legal_hold(&query, persisted_legal_hold.as_ref())?;
    let included_acts = book_acts
        .iter()
        .filter(|act| package_docs.iter().any(|doc| doc.act_id == Some(act.id)))
        .cloned()
        .collect::<Vec<_>>();

    let created_at = stable_package_time(&package_docs);
    let mut files = Vec::new();
    for doc in &package_docs {
        files.push(with_ids(
            PackageFileInput::pdfa_document(
                doc.document_id,
                doc.act_id.map(|act_id| act_id.0),
                doc.document.pdf_bytes.clone(),
            ),
            doc,
        ));
        files.push(with_ids(
            PackageFileInput::new(
                format!("metadata/{}.json", doc.document_id),
                PackageFileRole::Metadata,
                JSON_CONTENT_TYPE,
                metadata_sidecar_bytes(book_id, doc)?,
            ),
            doc,
        ));
        files.push(with_ids(
            PackageFileInput::evidence_report(
                doc.document_id,
                evidence_report_bytes(book_id, doc)?,
            ),
            doc,
        ));
        append_signed_sidecars(&mut files, doc)?;
    }

    if let Some(hold) = legal_hold.as_ref() {
        files.push(PackageFileInput::new(
            "evidence/legal-hold.json",
            PackageFileRole::EvidenceReport,
            JSON_CONTENT_TYPE,
            legal_hold_evidence_bytes(book_id, created_at, hold)?,
        ));
    }

    let package_id = stable_package_id(entity_id.0, book_id.0, created_at, &files);
    let mut input = PackageBuildInput::new(package_id, created_at, entity_id.0, book_id.0);
    input.act_ids = included_acts.iter().map(|act| act.id.0).collect();
    input.document_ids = package_docs.iter().map(|doc| doc.document_id).collect();
    input.producer = ProducerMetadata {
        name: entity_name.clone(),
        system: "Chancela".to_owned(),
    };
    input.provenance = provenance(&included_acts, &package_docs);
    input.rights = RightsMetadata {
        holder: Some(entity_name),
        license: None,
        access_note: Some("Chancela internal preservation package".to_owned()),
    };
    input.languages = vec!["pt-PT".to_owned()];
    input.retention = RetentionInstructions {
        legal_hold: legal_hold.is_some(),
        ..RetentionInstructions::default()
    };
    input.preservation_level = PreservationLevel::Managed;
    input.files = files;

    let package = build_archive_package(input)
        .map_err(|e| ApiError::Internal(format!("archive package build failed: {e}")))?;
    validate_package(&package.bytes)
        .map_err(|e| ApiError::Internal(format!("archive package self-validation failed: {e}")))?;
    let filename = format!("chancela-preservation-book-{id}.zip");
    Response::builder()
        .header(CONTENT_TYPE, ZIP_CONTENT_TYPE)
        .header(
            CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(package.bytes))
        .map_err(|e| ApiError::Internal(format!("failed to build archive package response: {e}")))
}

fn legal_hold_reason(query: &ExportArchivePackageQuery) -> Result<Option<String>, ApiError> {
    if !query.legal_hold {
        return Ok(None);
    }
    let reason = query
        .legal_hold_reason
        .as_deref()
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable("legal_hold_reason is required when legal_hold=true".to_owned())
        })?;
    Ok(Some(reason.to_owned()))
}

fn package_legal_hold(
    query: &ExportArchivePackageQuery,
    persisted: Option<&LegalHold>,
) -> Result<Option<PackageLegalHold>, ApiError> {
    if let Some(reason) = legal_hold_reason(query)? {
        return Ok(Some(PackageLegalHold {
            reason,
            persistence: "export_time_only; this endpoint does not persist legal-hold state",
            actor: None,
            set_at: None,
        }));
    }
    Ok(persisted.map(|hold| PackageLegalHold {
        reason: hold.reason.clone(),
        persistence: "persisted_book_state",
        actor: Some(hold.actor.clone()),
        set_at: Some(hold.set_at),
    }))
}

async fn load_book_archive_inventory(
    state: &AppState,
    book_id: BookId,
) -> Result<BookArchiveInventory, ApiError> {
    let (entity_id, entity_name, book_state, persisted_legal_hold, book_acts) = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let acts = state.acts.read().await;
        let book = books.get(&book_id).ok_or(ApiError::NotFound)?;
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        let mut book_acts = acts
            .values()
            .filter(|act| act.book_id == book_id)
            .cloned()
            .collect::<Vec<_>>();
        book_acts.sort_by(|left, right| {
            left.ata_number
                .cmp(&right.ata_number)
                .then_with(|| left.id.0.cmp(&right.id.0))
        });
        (
            book.entity_id,
            entity.name.clone(),
            book.state,
            book.legal_hold.clone(),
            book_acts,
        )
    };

    let mut package_docs = Vec::new();
    for document in load_owner_documents(state, ActId(book_id.0)).await? {
        package_docs.push(PackageDocument {
            owner_kind: "book",
            owner_id: book_id.0,
            act_id: None,
            document_id: parse_document_id(&document)?,
            document,
            signed: None,
        });
    }
    for act in book_acts.iter().filter(|act| act.ata_number.is_some()) {
        if let Some(document) = crate::documents::load_document(state, act.id).await? {
            let signed = load_signed_document(state, act.id).await?;
            let document_id = parse_document_id(&document)?;
            let signed = match signed {
                Some(signed) if signed.document_id == document_id.to_string() => Some(signed),
                Some(signed) => {
                    return Err(ApiError::Conflict(format!(
                        "stored signed document for act {} references document {}, but the canonical archived document is {}",
                        act.id, signed.document_id, document_id
                    )));
                }
                None => None,
            };
            package_docs.push(PackageDocument {
                owner_kind: "act",
                owner_id: act.id.0,
                act_id: Some(act.id),
                document_id,
                document,
                signed,
            });
        }
    }
    package_docs.sort_by(|left, right| {
        left.owner_kind
            .cmp(right.owner_kind)
            .then_with(|| left.owner_id.cmp(&right.owner_id))
            .then_with(|| left.document_id.cmp(&right.document_id))
    });

    Ok(BookArchiveInventory {
        entity_id,
        entity_name,
        book_state,
        persisted_legal_hold,
        book_acts,
        package_docs,
    })
}

fn disposal_status(book_id: BookId, inventory: &BookArchiveInventory) -> DisposalStatusView {
    let mut reasons = Vec::new();
    if inventory.package_docs.is_empty() {
        reasons.push(DisposalReason {
            code: "no_preserved_documents",
            blocking: true,
            message: "book has no preserved PDF/A documents to prove before disposal".to_owned(),
        });
    }
    if let Some(hold) = inventory.persisted_legal_hold.as_ref() {
        reasons.push(DisposalReason {
            code: "active_persisted_legal_hold",
            blocking: true,
            message: format!(
                "active persisted legal hold set by {} at {}: {}",
                hold.actor,
                rfc3339(hold.set_at),
                hold.reason
            ),
        });
    }
    let blocked = reasons.iter().any(|reason| reason.blocking);
    DisposalStatusView {
        book_id: book_id.0,
        entity_id: inventory.entity_id.0,
        book_state: inventory.book_state,
        eligible: !blocked,
        blocked,
        active_persisted_legal_hold: inventory.persisted_legal_hold.is_some(),
        export_time_legal_hold_persisted: false,
        signed_evidence: signed_evidence_summary(&inventory.package_docs),
        reasons,
    }
}

fn signed_evidence_summary(docs: &[PackageDocument]) -> SignedEvidenceSummary {
    let signed_documents = docs.iter().filter(|doc| doc.signed.is_some()).count();
    let documents_total = docs.len();
    SignedEvidenceSummary {
        present: signed_documents > 0,
        documents_total,
        signed_documents,
        unsigned_documents: documents_total.saturating_sub(signed_documents),
    }
}

fn would_delete_manifest(book_id: BookId, inventory: &BookArchiveInventory) -> WouldDeleteManifest {
    WouldDeleteManifest {
        package_profile: PACKAGE_PROFILE,
        book_id: book_id.0,
        entity_id: inventory.entity_id.0,
        book_state: inventory.book_state,
        source_records: source_record_targets(book_id, inventory),
        package_members: package_member_targets(&inventory.package_docs),
    }
}

fn source_record_targets(
    book_id: BookId,
    inventory: &BookArchiveInventory,
) -> Vec<WouldDeleteTarget> {
    let mut targets = vec![WouldDeleteTarget {
        kind: "book",
        id: book_id.to_string(),
        act_id: None,
        document_id: None,
        path: None,
        content_type: None,
    }];
    targets.extend(inventory.book_acts.iter().map(|act| WouldDeleteTarget {
        kind: "act",
        id: act.id.to_string(),
        act_id: Some(act.id.0),
        document_id: None,
        path: None,
        content_type: None,
    }));
    for doc in &inventory.package_docs {
        targets.push(WouldDeleteTarget {
            kind: "document",
            id: doc.document_id.to_string(),
            act_id: doc.act_id.map(|act_id| act_id.0),
            document_id: Some(doc.document_id),
            path: None,
            content_type: None,
        });
        if let Some(signed) = &doc.signed {
            targets.push(WouldDeleteTarget {
                kind: "signed_document",
                id: signed.act_id.to_string(),
                act_id: Some(signed.act_id.0),
                document_id: Some(doc.document_id),
                path: None,
                content_type: None,
            });
        }
    }
    targets
}

fn package_member_targets(docs: &[PackageDocument]) -> Vec<WouldDeleteTarget> {
    let mut targets = vec![WouldDeleteTarget {
        kind: "archive_manifest",
        id: "manifest.json".to_owned(),
        act_id: None,
        document_id: None,
        path: Some("manifest.json".to_owned()),
        content_type: Some(JSON_CONTENT_TYPE),
    }];
    for doc in docs {
        targets.push(package_member_target(
            "pdfa_document",
            doc,
            format!("documents/{}.pdf", doc.document_id),
            "application/pdf",
        ));
        targets.push(package_member_target(
            "document_metadata",
            doc,
            format!("metadata/{}.json", doc.document_id),
            JSON_CONTENT_TYPE,
        ));
        targets.push(package_member_target(
            "signature_evidence",
            doc,
            format!("evidence/{}.json", doc.document_id),
            JSON_CONTENT_TYPE,
        ));
        if let Some(signed) = &doc.signed {
            targets.push(package_member_target(
                "signed_pdf",
                doc,
                format!("signed/{}.pdf", doc.document_id),
                signed_pdf_profile(signed.timestamp_token_der.is_some()),
            ));
            targets.push(package_member_target(
                "signing_report",
                doc,
                format!("signing/{}.json", doc.document_id),
                JSON_CONTENT_TYPE,
            ));
            targets.push(package_member_target(
                "signer_certificate",
                doc,
                format!("evidence/{}-signer-cert.der", doc.document_id),
                CERT_CONTENT_TYPE,
            ));
            if signed.timestamp_token_der.is_some() {
                targets.push(package_member_target(
                    "timestamp_token",
                    doc,
                    format!("evidence/{}-timestamp-token.tsr", doc.document_id),
                    TIMESTAMP_TOKEN_CONTENT_TYPE,
                ));
            }
        }
    }
    targets
}

fn package_member_target(
    kind: &'static str,
    doc: &PackageDocument,
    path: String,
    content_type: &'static str,
) -> WouldDeleteTarget {
    WouldDeleteTarget {
        kind,
        id: path.clone(),
        act_id: doc.act_id.map(|act_id| act_id.0),
        document_id: Some(doc.document_id),
        path: Some(path),
        content_type: Some(content_type),
    }
}

async fn load_owner_documents(
    state: &AppState,
    owner: ActId,
) -> Result<Vec<StoredDocument>, ApiError> {
    if let Some(store) = &state.store {
        return store
            .documents_for_act(owner)
            .map_err(|e| ApiError::Internal(format!("document store read failed: {e}")));
    }
    Ok(state
        .documents
        .read()
        .await
        .get(&owner)
        .cloned()
        .into_iter()
        .collect())
}

async fn load_signed_document(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<StoredSignedDocument>, ApiError> {
    if let Some(doc) = state.signed_documents.read().await.get(&act_id).cloned() {
        return Ok(Some(doc));
    }
    if let Some(store) = &state.store {
        return store
            .signed_document_for_act(act_id)
            .map_err(|e| ApiError::Internal(format!("signed document store read failed: {e}")));
    }
    Ok(None)
}

fn parse_document_id(document: &StoredDocument) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&document.id)
        .map_err(|e| ApiError::Conflict(format!("stored document id is not a UUID: {e}")))
}

fn validate_archive_inventory(book_id: BookId, docs: &[PackageDocument]) -> Result<(), ApiError> {
    let mut document_ids = BTreeSet::new();
    for doc in docs {
        if !document_ids.insert(doc.document_id) {
            return Err(ApiError::Conflict(format!(
                "document id {} appears more than once in archive inventory for book {}",
                doc.document_id, book_id
            )));
        }
        validate_stored_document(book_id, doc)?;
        if let Some(signed) = &doc.signed {
            validate_stored_signed_document(doc, signed)?;
        }
    }
    Ok(())
}

fn validate_stored_document(book_id: BookId, doc: &PackageDocument) -> Result<(), ApiError> {
    let context = format!(
        "stored document {} for {} {} in book {}",
        doc.document_id, doc.owner_kind, doc.owner_id, book_id
    );
    if doc.document.id != doc.document_id.to_string() {
        return Err(ApiError::Conflict(format!(
            "{context} has non-canonical document id metadata {:?}",
            doc.document.id
        )));
    }
    if doc.document.template_id.trim().is_empty() {
        return Err(ApiError::Conflict(format!(
            "{context} has empty template metadata"
        )));
    }
    if doc.document.profile != crate::documents::PDFA_PROFILE {
        return Err(ApiError::Conflict(format!(
            "{context} has unexpected preservation profile {:?}",
            doc.document.profile
        )));
    }
    if doc.document.pdf_bytes.is_empty() {
        return Err(ApiError::Conflict(format!(
            "{context} has no preserved PDF bytes"
        )));
    }
    if !looks_like_pdf(&doc.document.pdf_bytes) {
        return Err(ApiError::Conflict(format!(
            "{context} does not start with a PDF header"
        )));
    }
    validate_digest(
        &context,
        "pdf_digest",
        &doc.document.pdf_digest,
        &doc.document.pdf_bytes,
    )
}

fn validate_stored_signed_document(
    doc: &PackageDocument,
    signed: &StoredSignedDocument,
) -> Result<(), ApiError> {
    let context = format!(
        "stored signed document for act {} and document {}",
        signed.act_id, doc.document_id
    );
    if Some(signed.act_id) != doc.act_id {
        return Err(ApiError::Conflict(format!(
            "{context} is attached to a different archive owner"
        )));
    }
    if signed.document_id != doc.document_id.to_string() {
        return Err(ApiError::Conflict(format!(
            "{context} references document {}, not {}",
            signed.document_id, doc.document_id
        )));
    }
    if signed.signature_family.trim().is_empty() || signed.evidentiary_level.trim().is_empty() {
        return Err(ApiError::Conflict(format!(
            "{context} has incomplete signature metadata"
        )));
    }
    if signed.signer_cert_der.is_empty() {
        return Err(ApiError::Conflict(format!(
            "{context} has no signer certificate bytes"
        )));
    }
    if signed.signed_pdf_bytes.is_empty() {
        return Err(ApiError::Conflict(format!(
            "{context} has no signed PDF bytes"
        )));
    }
    if !looks_like_pdf(&signed.signed_pdf_bytes) {
        return Err(ApiError::Conflict(format!(
            "{context} does not start with a PDF header"
        )));
    }
    if signed.signed_at < signed.signing_time {
        return Err(ApiError::Conflict(format!(
            "{context} has signed_at before signing_time"
        )));
    }
    if signed
        .timestamp_token_der
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        return Err(ApiError::Conflict(format!(
            "{context} has an empty timestamp token"
        )));
    }
    validate_digest(
        &context,
        "signed_pdf_digest",
        &signed.signed_pdf_digest,
        &signed.signed_pdf_bytes,
    )
}

fn validate_digest(
    context: &str,
    label: &str,
    claimed: &str,
    bytes: &[u8],
) -> Result<(), ApiError> {
    if !is_sha256_hex(claimed) {
        return Err(ApiError::Conflict(format!(
            "{context} has invalid {label} metadata"
        )));
    }
    let actual = sha256_hex(bytes);
    if claimed != actual {
        return Err(ApiError::Conflict(format!(
            "{context} {label} mismatch: metadata {claimed}, actual {actual}"
        )));
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn looks_like_pdf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
}

fn with_ids(mut input: PackageFileInput, doc: &PackageDocument) -> PackageFileInput {
    input.document_id = Some(doc.document_id);
    input.act_id = doc.act_id.map(|act_id| act_id.0);
    input
}

fn append_signed_sidecars(
    files: &mut Vec<PackageFileInput>,
    doc: &PackageDocument,
) -> Result<(), ApiError> {
    let Some(signed) = &doc.signed else {
        return Ok(());
    };

    files.push(with_ids(
        PackageFileInput::new(
            format!("signed/{}.pdf", doc.document_id),
            PackageFileRole::Other,
            signed_pdf_profile(signed.timestamp_token_der.is_some()),
            signed.signed_pdf_bytes.clone(),
        ),
        doc,
    ));
    files.push(with_ids(
        PackageFileInput::signing_report(doc.document_id, signing_report_bytes(doc)?),
        doc,
    ));
    files.push(with_ids(
        PackageFileInput::new(
            format!("evidence/{}-signer-cert.der", doc.document_id),
            PackageFileRole::EvidenceReport,
            CERT_CONTENT_TYPE,
            signed.signer_cert_der.clone(),
        ),
        doc,
    ));
    if let Some(token) = &signed.timestamp_token_der {
        files.push(with_ids(
            PackageFileInput::new(
                format!("evidence/{}-timestamp-token.tsr", doc.document_id),
                PackageFileRole::EvidenceReport,
                TIMESTAMP_TOKEN_CONTENT_TYPE,
                token.clone(),
            ),
            doc,
        ));
    }
    Ok(())
}

fn metadata_sidecar_bytes(book_id: BookId, doc: &PackageDocument) -> Result<Vec<u8>, ApiError> {
    let signed = doc
        .signed
        .as_ref()
        .map(|signed| signed_metadata(doc, signed));
    serde_json::to_vec_pretty(&DocumentMetadataSidecar {
        package_profile: PACKAGE_PROFILE,
        owner: OwnerMetadata {
            kind: doc.owner_kind,
            id: doc.owner_id,
            book_id: book_id.0,
        },
        document: DocumentMetadata {
            id: doc.document_id,
            template_id: &doc.document.template_id,
            profile: &doc.document.profile,
            created_at: rfc3339(doc.document.created_at),
            pdf_digest: &doc.document.pdf_digest,
        },
        signed,
    })
    .map_err(|e| ApiError::Internal(format!("document metadata serialization failed: {e}")))
}

fn signing_report_bytes(doc: &PackageDocument) -> Result<Vec<u8>, ApiError> {
    let Some(signed) = &doc.signed else {
        return Ok(Vec::new());
    };
    serde_json::to_vec_pretty(&signed_metadata(doc, signed))
        .map_err(|e| ApiError::Internal(format!("signing metadata serialization failed: {e}")))
}

fn evidence_report_bytes(book_id: BookId, doc: &PackageDocument) -> Result<Vec<u8>, ApiError> {
    let (status, reason, source, signature) = match &doc.signed {
        Some(signed) => (
            "signed",
            None,
            "signed_documents",
            Some(signature_evidence(doc, signed)),
        ),
        None if doc.act_id.is_some() => (
            "not_signed",
            Some("no stored signature metadata matched this act document at export time"),
            "documents",
            None,
        ),
        None => (
            "not_available",
            Some("book-level document is not an act signature target"),
            "documents",
            None,
        ),
    };

    serde_json::to_vec_pretty(&ValidationEvidenceReport {
        package_profile: PACKAGE_PROFILE,
        report_kind: "signature_validation_evidence",
        status,
        reason,
        owner: OwnerMetadata {
            kind: doc.owner_kind,
            id: doc.owner_id,
            book_id: book_id.0,
        },
        document_id: doc.document_id,
        act_id: doc.act_id.map(|act_id| act_id.0),
        source,
        archive_export_revalidated: false,
        signature,
    })
    .map_err(|e| ApiError::Internal(format!("evidence report serialization failed: {e}")))
}

fn legal_hold_evidence_bytes(
    book_id: BookId,
    created_at: OffsetDateTime,
    hold: &PackageLegalHold,
) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec_pretty(&LegalHoldEvidenceReport {
        package_profile: PACKAGE_PROFILE,
        report_kind: "retention_legal_hold_evidence",
        status: "active",
        legal_hold: true,
        reason: &hold.reason,
        scope: "book_archive_package_export",
        persistence: hold.persistence,
        actor: hold.actor.as_deref(),
        set_at: hold.set_at.map(rfc3339),
        created_at: rfc3339(created_at),
        book_id: book_id.0,
    })
    .map_err(|e| ApiError::Internal(format!("legal hold evidence serialization failed: {e}")))
}

fn signed_metadata<'a>(
    doc: &'a PackageDocument,
    signed: &'a StoredSignedDocument,
) -> SignedMetadata<'a> {
    SignedMetadata {
        signed_pdf_digest: &signed.signed_pdf_digest,
        signature_family: &signed.signature_family,
        evidentiary_level: &signed.evidentiary_level,
        trusted_list_status: signed.trusted_list_status.as_deref(),
        signer_cert_subject: signed.signer_cert_subject.as_deref(),
        signing_time: rfc3339(signed.signing_time),
        signed_at: rfc3339(signed.signed_at),
        signer_certificate_path: format!("evidence/{}-signer-cert.der", doc.document_id),
        timestamp_token_path: signed
            .timestamp_token_der
            .as_ref()
            .map(|_| format!("evidence/{}-timestamp-token.tsr", doc.document_id)),
        signed_pdf_path: format!("signed/{}.pdf", doc.document_id),
    }
}

fn signature_evidence<'a>(
    doc: &'a PackageDocument,
    signed: &'a StoredSignedDocument,
) -> SignatureEvidence<'a> {
    let timestamp_token_path = signed
        .timestamp_token_der
        .as_ref()
        .map(|_| format!("evidence/{}-timestamp-token.tsr", doc.document_id));
    let timestamp_token_sha256 = signed
        .timestamp_token_der
        .as_ref()
        .map(|token| sha256_hex(token));
    let has_timestamp = signed.timestamp_token_der.is_some();
    let timestamp_trust = signed
        .timestamp_trust_report_json
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok());
    let timestamp_trust_persistence = if has_timestamp {
        if timestamp_trust.is_some() {
            "persisted_technical_timestamp_trust_report"
        } else {
            "not_persisted_full_validator_inputs"
        }
    } else {
        "not_applicable"
    };

    SignatureEvidence {
        signed_pdf: SignedPdfEvidence {
            path: format!("signed/{}.pdf", doc.document_id),
            content_type: signed_pdf_profile(has_timestamp),
            sha256: &signed.signed_pdf_digest,
        },
        signature: SignatureMetadataEvidence {
            family: &signed.signature_family,
            evidentiary_level: &signed.evidentiary_level,
            trusted_list_status: signed.trusted_list_status.as_deref(),
            signer_cert_subject: signed.signer_cert_subject.as_deref(),
            signing_time: rfc3339(signed.signing_time),
            signed_at: rfc3339(signed.signed_at),
        },
        signer_certificate: SignerCertificateEvidence {
            path: format!("evidence/{}-signer-cert.der", doc.document_id),
            sha256: sha256_hex(&signed.signer_cert_der),
            subject: signed.signer_cert_subject.as_deref(),
        },
        timestamp_token: TimestampTokenEvidence {
            present: has_timestamp,
            path: timestamp_token_path,
            sha256: timestamp_token_sha256,
        },
        timestamp_trust,
        dss: dss_evidence_report(&signed.signed_pdf_bytes, has_timestamp),
        persisted_validation: PersistedValidationEvidence {
            basis: "stored signed document metadata; signed routes persist this row only after SIG-24 validation succeeds",
            byte_range_covers_whole_file_except_contents: "validated_before_persistence",
            signer_certificate_matches_expected_certificate: "validated_before_persistence",
            signature_timestamp: if has_timestamp {
                "present_and_validated_before_persistence"
            } else {
                "not_present"
            },
            timestamp_trust: timestamp_trust_persistence,
            cryptographic_revalidation_at_export: "not_performed",
        },
    }
}

impl DssEvidenceReport {
    fn unavailable() -> Self {
        Self {
            basis: DSS_BASIS,
            present: false,
            vri_count: 0,
            certificate_count: 0,
            ocsp_count: 0,
            crl_count: 0,
            certificate_sha256: Vec::new(),
            ocsp_sha256: Vec::new(),
            crl_sha256: Vec::new(),
            revocation_evidence_present: false,
            local_b_lt_style_evidence_present: false,
            live_revocation_fetching: false,
            production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
            legal_b_lt_claimed: false,
            inspection_status: DSS_INSPECTION_UNAVAILABLE,
        }
    }

    fn from_report(report: &chancela_pades::DssReport, has_timestamp: bool) -> Self {
        let revocation_evidence_present = report.has_revocation_evidence();
        Self {
            basis: DSS_BASIS,
            present: report.present,
            vri_count: report.vri_count,
            certificate_count: report.certificate_count(),
            ocsp_count: report.ocsp_count(),
            crl_count: report.crl_count(),
            certificate_sha256: dss_hashes_hex(&report.certificate_hashes),
            ocsp_sha256: dss_hashes_hex(&report.ocsp_hashes),
            crl_sha256: dss_hashes_hex(&report.crl_hashes),
            revocation_evidence_present,
            local_b_lt_style_evidence_present: has_timestamp && revocation_evidence_present,
            live_revocation_fetching: false,
            production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
            legal_b_lt_claimed: false,
            inspection_status: DSS_INSPECTION_INSPECTED,
        }
    }
}

fn dss_evidence_report(pdf_bytes: &[u8], has_timestamp: bool) -> DssEvidenceReport {
    match chancela_pades::inspect_dss(pdf_bytes) {
        Ok(report) => DssEvidenceReport::from_report(&report, has_timestamp),
        Err(_) => DssEvidenceReport::unavailable(),
    }
}

fn dss_hashes_hex(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(crate::hex::hex).collect()
}

fn stable_package_time(docs: &[PackageDocument]) -> OffsetDateTime {
    docs.iter()
        .flat_map(|doc| {
            [
                Some(doc.document.created_at),
                doc.signed.as_ref().map(|signed| signed.signed_at),
            ]
        })
        .flatten()
        .max()
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn stable_package_id(
    entity_id: Uuid,
    book_id: Uuid,
    created_at: OffsetDateTime,
    files: &[PackageFileInput],
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(PACKAGE_PROFILE.as_bytes());
    hasher.update(entity_id.as_bytes());
    hasher.update(book_id.as_bytes());
    hasher.update(rfc3339(created_at).as_bytes());
    let mut sorted = files.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.path.cmp(&right.path));
    for file in sorted {
        hasher.update(file.path.as_bytes());
        hasher.update(file.content_type.as_bytes());
        hasher.update(format!("{:?}", file.role).as_bytes());
        hasher.update(Sha256::digest(&file.bytes));
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn provenance(acts: &[Act], docs: &[PackageDocument]) -> Vec<Provenance> {
    let mut out = acts
        .iter()
        .map(|act| Provenance {
            source: ProvenanceSource::SealedAct,
            reference: act.id.to_string(),
            captured_at: docs
                .iter()
                .find(|doc| doc.act_id == Some(act.id))
                .map(|doc| doc.document.created_at),
        })
        .collect::<Vec<_>>();
    if let Some(book_doc) = docs.iter().find(|doc| doc.owner_kind == "book") {
        out.push(Provenance {
            source: ProvenanceSource::UserEntry,
            reference: format!("book:{}", book_doc.owner_id),
            captured_at: Some(book_doc.document.created_at),
        });
    }
    out
}

fn rfc3339(value: OffsetDateTime) -> String {
    value.format(&Rfc3339).unwrap_or_default()
}

fn signed_pdf_profile(has_timestamp: bool) -> &'static str {
    if has_timestamp {
        SIGNED_PDF_B_T_PROFILE
    } else {
        SIGNED_PDF_B_B_PROFILE
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    crate::hex::hex(&digest)
}
