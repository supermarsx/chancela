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
use chancela_core::{Act, ActId, ActState, BookId, BookState, LegalHold};
use chancela_store::{StoredDocument, StoredSignedDocument};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::actor::CurrentAttestor;
use crate::authz::{require_permission, scope_of_book};
use crate::error::ApiError;
use crate::privacy::{
    RetentionDisposalAction, RetentionPolicyId, RetentionPolicyRecord, RetentionPolicyStatus,
};

const PACKAGE_PROFILE: &str = "chancela-internal-preservation-package/v1";
const ZIP_CONTENT_TYPE: &str = "application/zip";
const JSON_CONTENT_TYPE: &str = "application/json";
const ARCHIVE_DISPOSAL_POLICY_SCOPE: &str = "book_archive";
const ARCHIVE_DISPOSAL_POLICY_CATEGORY: &str = "documents";
const ARCHIVE_DISPOSAL_EVENT_KIND: &str = "book.archive.disposal.execution_recorded";
const MAX_DISPOSAL_OPERATOR_NOTES_CHARS: usize = 4096;
const SIGNED_PDF_B_B_PROFILE: &str = "application/pdf; profile=PAdES-B-B";
const SIGNED_PDF_B_T_PROFILE: &str = "application/pdf; profile=PAdES-B-T";
const CERT_CONTENT_TYPE: &str = "application/pkix-cert";
const TIMESTAMP_TOKEN_CONTENT_TYPE: &str = "application/timestamp-reply";
const DSS_INSPECTION_INSPECTED: &str = "inspected_from_signed_pdf";
const DSS_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const PRODUCTION_B_LT_NOT_CLAIMED: &str = "not_claimed";
const DSS_BASIS: &str = "embedded_pdf_dss_catalog_inspection_only";
const DOC_TIMESTAMP_BASIS: &str = "embedded_pdf_doctimestamp_inspection_only";
const DOC_TIMESTAMP_INSPECTION_INSPECTED: &str = "inspected_from_signed_pdf";
const DOC_TIMESTAMP_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const RENEWAL_POLICY_NOT_CONFIGURED: &str = "not_configured";
const RENEWAL_POLICY_MANUAL_REVIEW: &str = "manual_review";
const ARCHIVE_EVIDENCE_INDEX_PATH: &str = "evidence/index.json";
const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND: &str = "external_validator_report_metadata";
const EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA: &str =
    "chancela-external-validator-report-evidence/v1";
const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX: &str = "evidence/external-validators/";
const EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN: &str =
    "evidence/external-validators/{case_id}-{validator_family}.json";
const TECHNICAL_METADATA_ONLY: &str = "technical_metadata_only";

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
    retention_policy_id: Option<String>,
    execution_request_id: Option<String>,
    operator_notes: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<DisposalExecutionView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalExecutionView {
    record: DisposalExecutionRecord,
    audit_event: DisposalAuditEvent,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalExecutionRecord {
    id: String,
    requested_at: String,
    actor: String,
    retention_policy: DisposalRetentionPolicyEvidence,
    candidate: DisposalRetentionCandidate,
    outcome: &'static str,
    execution_mode: &'static str,
    physical_deletion_performed: bool,
    limitation: &'static str,
    deleted: Vec<WouldDeleteTarget>,
    marked_disposed: Vec<WouldDeleteTarget>,
    package_members_recorded: Vec<WouldDeleteTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalAuditEvent {
    kind: &'static str,
    scope: String,
    seq: u64,
    hash: String,
    payload_digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalRetentionCandidate {
    scope: &'static str,
    category: &'static str,
    record_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisposalRetentionPolicyEvidence {
    id: String,
    name: String,
    scope: String,
    category: String,
    schedule_id: String,
    retention_period: String,
    legal_basis: String,
    disposal_action: RetentionDisposalAction,
    status: RetentionPolicyStatus,
    active: bool,
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

#[derive(Debug, Clone, Serialize)]
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
struct ArchiveEvidenceIndex {
    package_profile: &'static str,
    index_kind: &'static str,
    status_scope: &'static str,
    generated_at: String,
    book_id: Uuid,
    package_manifest_path: &'static str,
    evidence_index_path: &'static str,
    documents: Vec<ArchiveDocumentEvidenceIndexEntry>,
    package_evidence: ArchivePackageEvidenceIndexEntry,
    external_validator_reports: ExternalValidatorReportEvidenceIndex,
}

#[derive(Serialize)]
struct ArchiveDocumentEvidenceIndexEntry {
    document_id: Uuid,
    act_id: Option<Uuid>,
    canonical_pdf_path: String,
    document_metadata_path: String,
    signature_evidence_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_pdf_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_metadata_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_certificate_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp_token_path: Option<String>,
}

#[derive(Serialize)]
struct ArchivePackageEvidenceIndexEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    legal_hold_evidence_path: Option<&'static str>,
}

#[derive(Serialize)]
struct ExternalValidatorReportEvidenceIndex {
    evidence_kind: &'static str,
    metadata_schema: &'static str,
    indexed_path_prefix: &'static str,
    indexed_path_pattern: &'static str,
    attachment_status: &'static str,
    status_scope: &'static str,
    attachments: Vec<ExternalValidatorReportEvidenceAttachmentIndex>,
}

#[derive(Serialize)]
struct ExternalValidatorReportEvidenceAttachmentIndex {
    case_id: String,
    validator_family: String,
    path: String,
    content_type: String,
    sha256: String,
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
    doc_timestamp: DocTimeStampEvidenceReport,
    renewal_policy: RenewalPolicyEvidenceReport,
    legal_b_lta_claimed: bool,
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
struct DocTimeStampEvidenceReport {
    basis: &'static str,
    present: bool,
    count: usize,
    token_sha256: Vec<String>,
    validations: Vec<DocTimeStampValidationEvidenceReport>,
    all_imprints_valid: bool,
    inspection_status: &'static str,
}

#[derive(Serialize)]
struct DocTimeStampValidationEvidenceReport {
    index: usize,
    object_id: String,
    byte_range: Option<[i64; 4]>,
    document_digest_sha256: Option<String>,
    token_imprint_sha256: Option<String>,
    token_hash_algorithm: Option<String>,
    status: &'static str,
    failure_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct RenewalPolicyEvidenceReport {
    status: &'static str,
    action: &'static str,
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

/// `POST /v1/books/{id}/archive/disposal` - `dry_run=true` simulates disposal, while
/// `dry_run=false` records a guarded non-destructive execution/evidence state. This slice never
/// physically deletes stored archive/source records.
pub async fn simulate_book_disposal(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
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

    let inventory = load_book_archive_inventory(&state, book_id).await?;
    let status = disposal_status(book_id, &inventory);
    if status.blocked {
        return Err(ApiError::Conflict(
            "disposição bloqueada; consulte os motivos de elegibilidade antes de executar"
                .to_owned(),
        ));
    }
    validate_archive_inventory(book_id, &inventory.package_docs)?;
    let would_delete = would_delete_manifest(book_id, &inventory);
    let execution = if req.dry_run {
        None
    } else {
        Some(
            execute_book_disposal(
                &state,
                book_id,
                &actor,
                &attestor,
                &req,
                &inventory,
                &would_delete,
            )
            .await?,
        )
    };
    Ok(Json(DisposalSimulationView {
        dry_run: req.dry_run,
        status,
        would_delete,
        execution,
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
    files.push(PackageFileInput::new(
        ARCHIVE_EVIDENCE_INDEX_PATH,
        PackageFileRole::EvidenceReport,
        JSON_CONTENT_TYPE,
        archive_evidence_index_bytes(book_id, created_at, &package_docs, legal_hold.is_some())?,
    ));

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
    if inventory.book_state != BookState::Closed {
        reasons.push(DisposalReason {
            code: "book_not_closed",
            blocking: true,
            message: format!(
                "book is {:?}; disposal execution requires a closed book chain",
                inventory.book_state
            ),
        });
    }
    let unsealed_count = inventory
        .book_acts
        .iter()
        .filter(|act| {
            act.ata_number.is_none() || !matches!(act.state, ActState::Sealed | ActState::Archived)
        })
        .count();
    if unsealed_count > 0 {
        reasons.push(DisposalReason {
            code: "unsealed_acts_present",
            blocking: true,
            message: format!(
                "{unsealed_count} act(s) are not sealed/archived with an assigned ata number"
            ),
        });
    }
    let documented_acts = inventory
        .package_docs
        .iter()
        .filter_map(|doc| doc.act_id.map(|act_id| act_id.0))
        .collect::<BTreeSet<_>>();
    let missing_document_count = inventory
        .book_acts
        .iter()
        .filter(|act| {
            matches!(act.state, ActState::Sealed | ActState::Archived)
                && act.ata_number.is_some()
                && !documented_acts.contains(&act.id.0)
        })
        .count();
    if missing_document_count > 0 {
        reasons.push(DisposalReason {
            code: "sealed_act_missing_preserved_document",
            blocking: true,
            message: format!(
                "{missing_document_count} sealed/archived act(s) have no preserved PDF/A document"
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

async fn execute_book_disposal(
    state: &AppState,
    book_id: BookId,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
    req: &DisposalSimulationRequest,
    inventory: &BookArchiveInventory,
    would_delete: &WouldDeleteManifest,
) -> Result<DisposalExecutionView, ApiError> {
    ensure_disposal_execution_environment(state).await?;
    let retention_policy = archive_disposal_retention_policy(state, req).await?;
    let execution_id = parse_execution_request_id(req.execution_request_id.as_deref())?;
    let actor_name = actor.resolve("api");
    let scope = archive_disposal_event_scope(inventory, book_id);
    let record = DisposalExecutionRecord {
        id: execution_id.to_string(),
        requested_at: rfc3339(OffsetDateTime::now_utc()),
        actor: actor_name.clone(),
        retention_policy: DisposalRetentionPolicyEvidence::from(&retention_policy),
        candidate: DisposalRetentionCandidate {
            scope: ARCHIVE_DISPOSAL_POLICY_SCOPE,
            category: ARCHIVE_DISPOSAL_POLICY_CATEGORY,
            record_id: format!("book:{book_id}"),
        },
        outcome: "disposed_mark_recorded",
        execution_mode: "non_destructive_evidence_only",
        physical_deletion_performed: false,
        limitation: "physical deletion of archive/source records is not implemented in this guarded slice; this records a durable disposal execution request/evidence state only",
        deleted: Vec::new(),
        marked_disposed: would_delete.source_records.clone(),
        package_members_recorded: would_delete.package_members.clone(),
        operator_notes: clean_disposal_operator_notes(req.operator_notes.as_deref())?,
    };
    let payload = serde_json::to_vec(&record)?;
    let mut ledger = state.ledger.write().await;
    if !ledger.integrity_report().healthy {
        return Err(ApiError::Conflict(
            "archive disposal execution blocked because the ledger integrity report is degraded"
                .to_owned(),
        ));
    }
    if !ledger
        .events()
        .iter()
        .any(|event| event.kind == "book.closed" && event.scope == scope)
    {
        return Err(ApiError::Conflict(
            "archive disposal execution requires a closed book chain with a book.closed event"
                .to_owned(),
        ));
    }
    if ledger
        .events()
        .iter()
        .any(|event| event.kind == ARCHIVE_DISPOSAL_EVENT_KIND && event.scope == scope)
    {
        return Err(ApiError::Conflict(
            "archive disposal execution was already recorded for this book; repeated execution is blocked"
                .to_owned(),
        ));
    }
    crate::try_append_event(
        &mut ledger,
        &actor_name,
        &scope,
        ARCHIVE_DISPOSAL_EVENT_KIND,
        Some("Archive disposal execution recorded without physical deletion"),
        &payload,
    )?;
    state.persist_write_through(&mut ledger, 1, |_| Ok(()))?;
    let event = ledger
        .events()
        .last()
        .expect("disposal execution event was just appended");
    let audit_event = DisposalAuditEvent {
        kind: ARCHIVE_DISPOSAL_EVENT_KIND,
        scope,
        seq: event.seq,
        hash: hex_bytes(&event.hash),
        payload_digest: hex_bytes(&event.payload_digest),
    };
    state.attest_latest(attestor, &ledger).await;

    Ok(DisposalExecutionView {
        record,
        audit_event,
    })
}

async fn ensure_disposal_execution_environment(state: &AppState) -> Result<(), ApiError> {
    if state.store.is_none()
        || state.retention_policies_path.is_none()
        || state.chain_status.is_none()
    {
        return Err(ApiError::Conflict(
            "archive disposal execution requires durable store-backed state; in-memory mode is dry-run only"
                .to_owned(),
        ));
    }
    if *state.degraded.read().await {
        return Err(ApiError::Conflict(
            "archive disposal execution blocked while the instance is in degraded read-only mode"
                .to_owned(),
        ));
    }
    if state
        .chain_status
        .as_ref()
        .is_some_and(|status| status.as_ref().is_err())
    {
        return Err(ApiError::Conflict(
            "archive disposal execution blocked because the boot ledger chain status is broken"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn archive_disposal_retention_policy(
    state: &AppState,
    req: &DisposalSimulationRequest,
) -> Result<RetentionPolicyRecord, ApiError> {
    let policy_id = parse_required_retention_policy_id(req.retention_policy_id.as_deref())?;
    let policies = state.retention_policies.read().await;
    let legal_hold_blockers = policies
        .values()
        .filter(|policy| {
            policy.active
                && policy.status == RetentionPolicyStatus::Active
                && policy.disposal_action == RetentionDisposalAction::LegalHold
                && retention_policy_value_matches(&policy.scope, ARCHIVE_DISPOSAL_POLICY_SCOPE)
                && retention_policy_value_matches(
                    &policy.category,
                    ARCHIVE_DISPOSAL_POLICY_CATEGORY,
                )
        })
        .map(|policy| policy.id.to_string())
        .collect::<Vec<_>>();
    if !legal_hold_blockers.is_empty() {
        return Err(ApiError::Conflict(format!(
            "archive disposal execution blocked by active legal-hold retention policy/policies: {}",
            legal_hold_blockers.join(", ")
        )));
    }

    let policy = policies
        .get(&policy_id)
        .cloned()
        .ok_or_else(|| ApiError::Conflict("requested retention policy is missing".to_owned()))?;
    validate_archive_disposal_policy(&policy)?;
    Ok(policy)
}

fn validate_archive_disposal_policy(policy: &RetentionPolicyRecord) -> Result<(), ApiError> {
    if !policy.active || policy.status != RetentionPolicyStatus::Active {
        return Err(ApiError::Conflict(
            "requested retention policy is not active".to_owned(),
        ));
    }
    if !retention_policy_value_matches(&policy.scope, ARCHIVE_DISPOSAL_POLICY_SCOPE)
        || !retention_policy_value_matches(&policy.category, ARCHIVE_DISPOSAL_POLICY_CATEGORY)
    {
        return Err(ApiError::Conflict(
            "requested retention policy does not match archive disposal scope/category".to_owned(),
        ));
    }
    for (field, value) in [
        ("name", &policy.name),
        ("schedule_id", &policy.schedule_id),
        ("retention_period", &policy.retention_period),
        ("legal_basis", &policy.legal_basis),
    ] {
        if value.trim().is_empty() {
            return Err(ApiError::Conflict(format!(
                "requested retention policy has an invalid empty {field}"
            )));
        }
    }
    match policy.disposal_action {
        RetentionDisposalAction::Archive => Ok(()),
        RetentionDisposalAction::Delete | RetentionDisposalAction::Anonymize => {
            Err(ApiError::Conflict(
                "delete/anonymize retention execution is unsupported in this guarded archive slice"
                    .to_owned(),
            ))
        }
        RetentionDisposalAction::LegalHold => Err(ApiError::Conflict(
            "active legal hold retention policies block archive disposal execution".to_owned(),
        )),
        RetentionDisposalAction::Review | RetentionDisposalAction::NoAction => {
            Err(ApiError::Conflict(
                "requested retention policy does not authorize archive disposal execution"
                    .to_owned(),
            ))
        }
    }
}

fn parse_required_retention_policy_id(raw: Option<&str>) -> Result<RetentionPolicyId, ApiError> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable("retention_policy_id is required when dry_run=false".to_owned())
        })?;
    Uuid::parse_str(value)
        .map(RetentionPolicyId)
        .map_err(|_| ApiError::Unprocessable("retention_policy_id must be a UUID".to_owned()))
}

fn parse_execution_request_id(raw: Option<&str>) -> Result<Uuid, ApiError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Uuid::new_v4());
    };
    Uuid::parse_str(value)
        .map_err(|_| ApiError::Unprocessable("execution_request_id must be a UUID".to_owned()))
}

fn clean_disposal_operator_notes(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    let Some(value) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_DISPOSAL_OPERATOR_NOTES_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "operator_notes must be at most {MAX_DISPOSAL_OPERATOR_NOTES_CHARS} characters"
        )));
    }
    Ok(Some(value.to_owned()))
}

fn retention_policy_value_matches(policy_value: &str, target: &str) -> bool {
    let policy_value = policy_value.trim();
    policy_value.eq_ignore_ascii_case(target) || policy_value.eq_ignore_ascii_case("all")
}

fn archive_disposal_event_scope(inventory: &BookArchiveInventory, book_id: BookId) -> String {
    format!("entity:{}/book:{}", inventory.entity_id, book_id)
}

impl From<&RetentionPolicyRecord> for DisposalRetentionPolicyEvidence {
    fn from(policy: &RetentionPolicyRecord) -> Self {
        Self {
            id: policy.id.to_string(),
            name: policy.name.clone(),
            scope: policy.scope.clone(),
            category: policy.category.clone(),
            schedule_id: policy.schedule_id.clone(),
            retention_period: policy.retention_period.clone(),
            legal_basis: policy.legal_basis.clone(),
            disposal_action: policy.disposal_action,
            status: policy.status,
            active: policy.active,
        }
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
    targets.push(WouldDeleteTarget {
        kind: "archive_evidence_index",
        id: ARCHIVE_EVIDENCE_INDEX_PATH.to_owned(),
        act_id: None,
        document_id: None,
        path: Some(ARCHIVE_EVIDENCE_INDEX_PATH.to_owned()),
        content_type: Some(JSON_CONTENT_TYPE),
    });
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

fn archive_evidence_index_bytes(
    book_id: BookId,
    created_at: OffsetDateTime,
    docs: &[PackageDocument],
    legal_hold: bool,
) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec_pretty(&ArchiveEvidenceIndex {
        package_profile: PACKAGE_PROFILE,
        index_kind: "archive_evidence_index",
        status_scope: TECHNICAL_METADATA_ONLY,
        generated_at: rfc3339(created_at),
        book_id: book_id.0,
        package_manifest_path: "manifest.json",
        evidence_index_path: ARCHIVE_EVIDENCE_INDEX_PATH,
        documents: docs.iter().map(archive_document_evidence_index).collect(),
        package_evidence: ArchivePackageEvidenceIndexEntry {
            legal_hold_evidence_path: legal_hold.then_some("evidence/legal-hold.json"),
        },
        external_validator_reports: external_validator_report_evidence_index(
            "no_external_validator_report_metadata_attached",
        ),
    })
    .map_err(|e| ApiError::Internal(format!("archive evidence index serialization failed: {e}")))
}

fn archive_document_evidence_index(doc: &PackageDocument) -> ArchiveDocumentEvidenceIndexEntry {
    ArchiveDocumentEvidenceIndexEntry {
        document_id: doc.document_id,
        act_id: doc.act_id.map(|act_id| act_id.0),
        canonical_pdf_path: format!("documents/{}.pdf", doc.document_id),
        document_metadata_path: format!("metadata/{}.json", doc.document_id),
        signature_evidence_path: format!("evidence/{}.json", doc.document_id),
        signed_pdf_path: doc
            .signed
            .as_ref()
            .map(|_| format!("signed/{}.pdf", doc.document_id)),
        signing_metadata_path: doc
            .signed
            .as_ref()
            .map(|_| format!("signing/{}.json", doc.document_id)),
        signer_certificate_path: doc
            .signed
            .as_ref()
            .map(|_| format!("evidence/{}-signer-cert.der", doc.document_id)),
        timestamp_token_path: doc.signed.as_ref().and_then(|signed| {
            signed
                .timestamp_token_der
                .as_ref()
                .map(|_| format!("evidence/{}-timestamp-token.tsr", doc.document_id))
        }),
    }
}

fn external_validator_report_evidence_index(
    attachment_status: &'static str,
) -> ExternalValidatorReportEvidenceIndex {
    ExternalValidatorReportEvidenceIndex {
        evidence_kind: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_KIND,
        metadata_schema: EXTERNAL_VALIDATOR_REPORT_EVIDENCE_SCHEMA,
        indexed_path_prefix: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PREFIX,
        indexed_path_pattern: EXTERNAL_VALIDATOR_REPORT_ARCHIVE_PATH_PATTERN,
        attachment_status,
        status_scope: TECHNICAL_METADATA_ONLY,
        attachments: Vec::new(),
    }
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
        doc_timestamp: doc_timestamp_evidence_report(&signed.signed_pdf_bytes),
        renewal_policy: RenewalPolicyEvidenceReport::not_configured(),
        legal_b_lta_claimed: false,
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

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("write to string");
    }
    out
}

impl DocTimeStampEvidenceReport {
    fn unavailable() -> Self {
        Self {
            basis: DOC_TIMESTAMP_BASIS,
            present: false,
            count: 0,
            token_sha256: Vec::new(),
            validations: Vec::new(),
            all_imprints_valid: false,
            inspection_status: DOC_TIMESTAMP_INSPECTION_UNAVAILABLE,
        }
    }

    fn from_report(report: &chancela_pades::DocTimeStampReport) -> Self {
        Self {
            basis: DOC_TIMESTAMP_BASIS,
            present: report.present,
            count: report.count,
            token_sha256: dss_hashes_hex(&report.token_hashes),
            validations: report
                .validations
                .iter()
                .map(DocTimeStampValidationEvidenceReport::from_validation)
                .collect(),
            all_imprints_valid: report.all_imprints_valid(),
            inspection_status: DOC_TIMESTAMP_INSPECTION_INSPECTED,
        }
    }
}

impl DocTimeStampValidationEvidenceReport {
    fn from_validation(validation: &chancela_pades::DocTimeStampValidation) -> Self {
        Self {
            index: validation.index,
            object_id: format!("{} {}", validation.object_id.0, validation.object_id.1),
            byte_range: validation.byte_range,
            document_digest_sha256: validation
                .document_digest
                .map(|digest| crate::hex::hex(&digest)),
            token_imprint_sha256: validation.token_imprint.as_deref().map(hex_bytes),
            token_hash_algorithm: validation.token_hash_algorithm.clone(),
            status: doc_timestamp_status(validation.status),
            failure_reason: validation.failure_reason.map(doc_timestamp_failure_reason),
        }
    }
}

impl RenewalPolicyEvidenceReport {
    fn not_configured() -> Self {
        Self {
            status: RENEWAL_POLICY_NOT_CONFIGURED,
            action: RENEWAL_POLICY_MANUAL_REVIEW,
        }
    }
}

fn doc_timestamp_evidence_report(pdf_bytes: &[u8]) -> DocTimeStampEvidenceReport {
    match chancela_pades::inspect_doc_timestamps(pdf_bytes) {
        Ok(report) => DocTimeStampEvidenceReport::from_report(&report),
        Err(_) => DocTimeStampEvidenceReport::unavailable(),
    }
}

fn doc_timestamp_status(status: chancela_pades::DocTimeStampSemanticStatus) -> &'static str {
    match status {
        chancela_pades::DocTimeStampSemanticStatus::Valid => "valid",
        chancela_pades::DocTimeStampSemanticStatus::Failed => "failed",
        chancela_pades::DocTimeStampSemanticStatus::Unsupported => "unsupported",
        _ => "unsupported",
    }
}

fn doc_timestamp_failure_reason(reason: chancela_pades::DocTimeStampFailureReason) -> &'static str {
    match reason {
        chancela_pades::DocTimeStampFailureReason::MissingByteRange => "missing_byte_range",
        chancela_pades::DocTimeStampFailureReason::InvalidByteRange => "invalid_byte_range",
        chancela_pades::DocTimeStampFailureReason::InvalidContents => "invalid_contents",
        chancela_pades::DocTimeStampFailureReason::NotSignedData => "not_signed_data",
        chancela_pades::DocTimeStampFailureReason::NotTstInfo => "not_tst_info",
        chancela_pades::DocTimeStampFailureReason::EmptyTstInfo => "empty_tst_info",
        chancela_pades::DocTimeStampFailureReason::MalformedToken => "malformed_token",
        chancela_pades::DocTimeStampFailureReason::UnsupportedHashAlgorithm => {
            "unsupported_hash_algorithm"
        }
        chancela_pades::DocTimeStampFailureReason::ImprintMismatch => "imprint_mismatch",
        _ => "unknown",
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use chancela_authz::{OWNER_ROLE_ID, RoleAssignment, Scope};
    use chancela_core::{ActState, Book, BookKind, Entity, EntityKind, MeetingChannel, Nipc};
    use std::path::PathBuf;

    use crate::actor::CurrentActor;
    use crate::users::{SecretSource, User, UserId};

    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir()
                .join(format!("chancela-archive-disposal-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    struct ArchiveFixture {
        state: AppState,
        _tmp: TempDir,
        book_id: BookId,
        policy_id: RetentionPolicyId,
    }

    impl ArchiveFixture {
        fn actor(&self) -> CurrentActor {
            CurrentActor::from_session_username(Some("owner".to_owned()))
        }
    }

    async fn seeded_archive_fixture() -> ArchiveFixture {
        let tmp = TempDir::new();
        let state = AppState::with_data_dir(tmp.dir.clone());
        seed_owner(&state).await;

        let entity = Entity::new(
            "Arquivo Teste, S.A.",
            Nipc::unvalidated("PT-ARCHIVE-1"),
            "Lisboa",
            EntityKind::SociedadeAnonima,
        );
        let mut book = Book::new(entity.id, BookKind::AssembleiaGeral);
        book.state = BookState::Closed;
        let mut act = Act::draft(book.id, "Ata de teste", MeetingChannel::Physical);
        act.state = ActState::Sealed;
        act.ata_number = Some(1);

        let pdf_bytes = b"%PDF-1.7\n% archive disposal test\n".to_vec();
        let document = StoredDocument {
            id: Uuid::new_v4().to_string(),
            act_id: act.id,
            template_id: "csc-ata-ag/v1".to_owned(),
            pdf_digest: sha256_hex(&pdf_bytes),
            profile: crate::documents::PDFA_PROFILE.to_owned(),
            created_at: OffsetDateTime::now_utc(),
            pdf_bytes,
        };
        let policy_id = RetentionPolicyId(Uuid::new_v4());
        let policy = RetentionPolicyRecord {
            id: policy_id,
            name: "Archive book documents".to_owned(),
            scope: ARCHIVE_DISPOSAL_POLICY_SCOPE.to_owned(),
            category: ARCHIVE_DISPOSAL_POLICY_CATEGORY.to_owned(),
            schedule_id: "archive-documents-v1".to_owned(),
            retention_period: "P7Y".to_owned(),
            legal_basis: "Approved retention schedule".to_owned(),
            disposal_action: RetentionDisposalAction::Archive,
            status: RetentionPolicyStatus::Active,
            active: true,
            notes: None,
            created_at: rfc3339(OffsetDateTime::now_utc()),
            created_by: "owner".to_owned(),
            updated_at: rfc3339(OffsetDateTime::now_utc()),
            updated_by: "owner".to_owned(),
        };

        state
            .entities
            .write()
            .await
            .insert(entity.id, entity.clone());
        state.books.write().await.insert(book.id, book.clone());
        state.acts.write().await.insert(act.id, act.clone());
        state
            .documents
            .write()
            .await
            .insert(act.id, document.clone());
        state
            .retention_policies
            .write()
            .await
            .insert(policy.id, policy);
        if let Some(path) = &state.retention_policies_path {
            let policies = state.retention_policies.read().await;
            crate::privacy::write_retention_policies_atomic(path, &policies)
                .expect("persist retention policy fixture");
        }

        {
            let mut ledger = state.ledger.write().await;
            ledger.append(
                "owner",
                &format!("entity:{}", entity.id),
                "entity.created",
                None,
                b"entity",
            );
            let book_scope = format!("entity:{}/book:{}", entity.id, book.id);
            ledger.append("owner", &book_scope, "book.opened", None, b"opened");
            ledger.append("owner", &book_scope, "book.closed", None, b"closed");
            state
                .persist_write_through(&mut ledger, 3, |tx| {
                    tx.upsert_entity(&entity)?;
                    tx.upsert_book(&book)?;
                    tx.upsert_act(&act)?;
                    tx.upsert_document(&document)?;
                    Ok(())
                })
                .expect("persist archive fixture");
        }

        ArchiveFixture {
            state,
            _tmp: tmp,
            book_id: book.id,
            policy_id,
        }
    }

    async fn seed_owner(state: &AppState) {
        let user = User {
            id: UserId(Uuid::new_v4()),
            username: "owner".to_owned(),
            display_name: "Owner".to_owned(),
            email: None,
            created_at: rfc3339(OffsetDateTime::now_utc()),
            active: true,
            password_hash: None,
            attestation_key: None,
            secret_source: SecretSource::Password,
            recovery_hash: None,
            role_assignments: vec![RoleAssignment::new(OWNER_ROLE_ID, Scope::Global)],
        };
        state.users.write().await.insert(user.id, user);
    }

    fn execution_request(policy_id: RetentionPolicyId) -> DisposalSimulationRequest {
        DisposalSimulationRequest {
            dry_run: false,
            retention_policy_id: Some(policy_id.to_string()),
            execution_request_id: Some(Uuid::new_v4().to_string()),
            operator_notes: Some("approved for archive disposal evidence".to_owned()),
        }
    }

    #[tokio::test]
    async fn eligible_execution_records_non_destructive_evidence() {
        let fixture = seeded_archive_fixture().await;
        let Json(view) = simulate_book_disposal(
            State(fixture.state.clone()),
            Path(fixture.book_id.0),
            fixture.actor(),
            CurrentAttestor::default(),
            Json(execution_request(fixture.policy_id)),
        )
        .await
        .expect("eligible execution succeeds");

        assert!(!view.dry_run);
        assert!(view.status.eligible);
        let execution = view.execution.expect("execution evidence");
        assert!(!execution.record.physical_deletion_performed);
        assert!(execution.record.deleted.is_empty());
        assert!(!execution.record.marked_disposed.is_empty());
        assert_eq!(
            execution.record.retention_policy.id,
            fixture.policy_id.to_string()
        );
        assert_eq!(execution.audit_event.kind, ARCHIVE_DISPOSAL_EVENT_KIND);

        let loaded = fixture
            .state
            .store
            .as_ref()
            .expect("durable store")
            .load()
            .expect("load durable ledger");
        assert!(loaded.ledger.events().iter().any(|event| {
            event.kind == ARCHIVE_DISPOSAL_EVENT_KIND && event.scope == execution.audit_event.scope
        }));
    }

    #[tokio::test]
    async fn execution_is_blocked_by_persisted_legal_hold() {
        let fixture = seeded_archive_fixture().await;
        {
            let mut books = fixture.state.books.write().await;
            let book = books.get_mut(&fixture.book_id).expect("book");
            book.legal_hold = Some(LegalHold {
                reason: "litigation hold".to_owned(),
                actor: "legal".to_owned(),
                set_at: OffsetDateTime::now_utc(),
            });
        }

        let err = simulate_book_disposal(
            State(fixture.state.clone()),
            Path(fixture.book_id.0),
            fixture.actor(),
            CurrentAttestor::default(),
            Json(execution_request(fixture.policy_id)),
        )
        .await
        .expect_err("legal hold blocks execution");
        assert!(matches!(err, ApiError::Conflict(message) if message.contains("bloqueada")));
    }

    #[tokio::test]
    async fn execution_blocks_degraded_and_in_memory_modes() {
        let fixture = seeded_archive_fixture().await;
        *fixture.state.degraded.write().await = true;
        let err = simulate_book_disposal(
            State(fixture.state.clone()),
            Path(fixture.book_id.0),
            fixture.actor(),
            CurrentAttestor::default(),
            Json(execution_request(fixture.policy_id)),
        )
        .await
        .expect_err("degraded mode blocks execution");
        assert!(matches!(err, ApiError::Conflict(message) if message.contains("degraded")));

        let err = ensure_disposal_execution_environment(&AppState::default())
            .await
            .expect_err("in-memory mode blocks execution");
        assert!(matches!(err, ApiError::Conflict(message) if message.contains("in-memory")));
    }

    #[tokio::test]
    async fn repeated_execution_for_same_book_is_blocked() {
        let fixture = seeded_archive_fixture().await;
        let _ = simulate_book_disposal(
            State(fixture.state.clone()),
            Path(fixture.book_id.0),
            fixture.actor(),
            CurrentAttestor::default(),
            Json(execution_request(fixture.policy_id)),
        )
        .await
        .expect("first execution succeeds");

        let err = simulate_book_disposal(
            State(fixture.state.clone()),
            Path(fixture.book_id.0),
            fixture.actor(),
            CurrentAttestor::default(),
            Json(execution_request(fixture.policy_id)),
        )
        .await
        .expect_err("second execution is blocked");
        assert!(matches!(err, ApiError::Conflict(message) if message.contains("already recorded")));
    }
}
