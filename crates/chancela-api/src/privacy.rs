//! Backend-first privacy / compliance endpoints.
//!
//! DSR exports are deliberately read-only and non-secret: they reuse safe user/accountability state
//! and never serialize stored credential material. DSR requests, processor records, and DPIA
//! records are kept in memory for ephemeral states and written through to JSON sidecars when a data
//! directory is configured; each lifecycle transition is still chained into the ledger.

use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chancela_authz::{
    Permission, RoleAssignment, RoleId, Scope, UserId as AuthzUserId, count_owner_admin_holders,
    last_owner_guard,
};
use chancela_core::{Book, BookState, LegalHold};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, Month, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, require_permission};
use crate::dto::{LedgerEventView, format_date};
use crate::error::ApiError;
use crate::sidecar_store::persist_users;
use crate::try_append_event;
use crate::users::{User, UserId, UserView};
use chancela_ledger::{
    SUBJECT_ERASED_KIND, SUBJECT_PROCESSING_RESTRICTED_KIND, SUBJECT_RECTIFICATION_KIND,
};

const FORMAT_VERSION: u32 = 1;
const DSR_CREATED_KIND: &str = "privacy.dsr.request.created";
const DSR_COMPLETED_KIND: &str = "privacy.dsr.request.completed";
const PROCESSOR_CREATED_KIND: &str = "privacy.processor.created";
const PROCESSOR_UPDATED_KIND: &str = "privacy.processor.updated";
const DPIA_CREATED_KIND: &str = "privacy.dpia.created";
const DPIA_UPDATED_KIND: &str = "privacy.dpia.updated";
const BREACH_PLAYBOOK_CREATED_KIND: &str = "privacy.breach.playbook.created";
const BREACH_PLAYBOOK_UPDATED_KIND: &str = "privacy.breach.playbook.updated";
const TRANSFER_CONTROL_CREATED_KIND: &str = "privacy.transfer.control.created";
const TRANSFER_CONTROL_UPDATED_KIND: &str = "privacy.transfer.control.updated";
const RETENTION_POLICY_CREATED_KIND: &str = "privacy.retention.policy.created";
const RETENTION_POLICY_UPDATED_KIND: &str = "privacy.retention.policy.updated";
const RETENTION_EXECUTION_REQUESTED_KIND: &str = "privacy.retention.execution.requested";
const RETENTION_EXECUTION_REVIEW_CLOSED_KIND: &str = "privacy.retention.execution.review.closed";
const RETENTION_CANDIDATE_RESOLUTION_RECORDED_KIND: &str =
    "privacy.retention.candidate.resolution.recorded";
const ARCHIVE_RETENTION_POLICY_SCOPE: &str = "book_archive";
const ARCHIVE_RETENTION_POLICY_CATEGORY: &str = "documents";
const RETENTION_PRIOR_BOUNDED_ARCHIVE_NEXT_STEP: &str = "Prior bounded archive evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.";
const RETENTION_PRIOR_BOUNDED_NO_ACTION_NEXT_STEP: &str = "Prior bounded no-action evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.";
const RETENTION_PRIOR_BOUNDED_GENERIC_NEXT_STEP: &str = "Prior bounded retention evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.";
const RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE: &str = "Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review.";
pub(crate) const PROCESSORS_FILE: &str = "privacy-processors.json";
pub(crate) const DPIAS_FILE: &str = "privacy-dpias.json";
pub(crate) const BREACH_PLAYBOOKS_FILE: &str = "privacy-breach-playbooks.json";
pub(crate) const TRANSFER_CONTROLS_FILE: &str = "privacy-transfer-controls.json";
pub(crate) const DSR_REQUESTS_FILE: &str = "privacy-dsr-requests.json";
pub(crate) const RETENTION_POLICIES_FILE: &str = "retention-policies.json";
pub(crate) const RETENTION_EXECUTIONS_FILE: &str = "privacy-retention-executions.json";
pub(crate) const RETENTION_CANDIDATE_RESOLUTIONS_FILE: &str =
    "privacy-retention-candidate-resolutions.json";
const MAX_DSR_EXECUTION_NOTE_CHARS: usize = 4096;
const MAX_DSR_REVIEW_CHARS: usize = 2048;
const MAX_DSR_AFFECTED_RECORDS: usize = 32;
const MAX_DSR_ERASURE_PLAN_ITEMS: usize = 16;
const MAX_DSR_AFFECTED_FIELD_CHARS: usize = 128;
const MAX_DSR_AFFECTED_RECORD_COUNT: u64 = 1_000_000_000;
const MAX_RETENTION_NAME_CHARS: usize = 160;
const MAX_RETENTION_FIELD_CHARS: usize = 128;
const MAX_RETENTION_TEXT_CHARS: usize = 4096;
const MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS: usize = 16;
const MAX_RETENTION_EXECUTION_EVIDENCE_LABEL_CHARS: usize = 64;
const MAX_PRIVACY_CONTROL_NAME_CHARS: usize = 160;
const MAX_PRIVACY_CONTROL_FIELD_CHARS: usize = 128;
const MAX_PRIVACY_CONTROL_TEXT_CHARS: usize = 4096;
const MAX_PRIVACY_CONTROL_LIST_ITEMS: usize = 32;
const MAX_PRIVACY_EVIDENCE_RECEIPTS: usize = 64;
pub(crate) const PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS: i64 = 365;
const SENSITIVE_EVIDENCE_MARKERS: &[&str] = &[
    "password_hash",
    "recovery_hash",
    "recovery_phrase",
    "api_key_secret",
    "bearer_token",
    "attestation_private_key",
];

#[derive(Serialize)]
pub struct PrivacyExport {
    pub exported_at: String,
    pub scope: String,
    pub format_version: u32,
    pub redaction_notes: Vec<&'static str>,
    pub exclusions: Vec<&'static str>,
    pub user: ExportUser,
    pub ledger_event_refs: Vec<LedgerEventView>,
}

#[derive(Serialize)]
pub struct ExportUser {
    #[serde(flatten)]
    pub profile: UserView,
    pub role_assignments: Vec<RoleAssignmentExport>,
}

#[derive(Serialize)]
pub struct RoleAssignmentExport {
    pub role_id: String,
    pub scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DsrRequestId(pub Uuid);

impl std::fmt::Display for DsrRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrRequestType {
    Export,
    Rectification,
    Erasure,
    Restriction,
}

impl DsrRequestType {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "export" => Ok(Self::Export),
            "rectification" => Ok(Self::Rectification),
            "erasure" => Ok(Self::Erasure),
            "restriction" => Ok(Self::Restriction),
            _ => Err(ApiError::Unprocessable(
                "invalid DSR request_type; expected export, rectification, erasure, or restriction"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrRequestStatus {
    Pending,
    Completed,
}

impl DsrRequestStatus {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "completed" => Ok(Self::Completed),
            _ => Err(ApiError::Unprocessable(
                "invalid DSR status; expected pending or completed".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrExecutionOutcome {
    Fulfilled,
    PartiallyFulfilled,
    Rejected,
    NoActionRequired,
}

impl DsrExecutionOutcome {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "fulfilled" => Ok(Self::Fulfilled),
            "partially_fulfilled" => Ok(Self::PartiallyFulfilled),
            "rejected" => Ok(Self::Rejected),
            "no_action_required" => Ok(Self::NoActionRequired),
            _ => Err(ApiError::Unprocessable(
                "invalid DSR execution outcome; expected fulfilled, partially_fulfilled, rejected, or no_action_required"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrAffectedRecordSummary {
    pub collection: String,
    pub action: String,
    pub count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrErasurePreflightStatus {
    BlockedImmutableLedger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrMutableSidecarAction {
    Redact,
    Anonymize,
    Delete,
    Retain,
    Review,
}

impl DsrMutableSidecarAction {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "redact" => Ok(Self::Redact),
            "anonymize" | "anonymise" => Ok(Self::Anonymize),
            "delete" => Ok(Self::Delete),
            "retain" => Ok(Self::Retain),
            "review" => Ok(Self::Review),
            _ => Err(ApiError::Unprocessable(
                "invalid erasure_plan.action; expected redact, anonymize, delete, retain, or review"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DsrMutableSidecarPlanStatus {
    Planned,
    Blocked,
    ManualReviewRequired,
    NotApplicable,
}

impl DsrMutableSidecarPlanStatus {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "planned" | "pending" => Ok(Self::Planned),
            "blocked" => Ok(Self::Blocked),
            "manual_review_required" | "review_required" => Ok(Self::ManualReviewRequired),
            "not_applicable" | "none" => Ok(Self::NotApplicable),
            "completed" | "executed" => Err(ApiError::Unprocessable(
                "erasure_plan.status cannot be completed; this API records preflight only and does not execute mutation"
                    .to_owned(),
            )),
            _ => Err(ApiError::Unprocessable(
                "invalid erasure_plan.status; expected planned, blocked, manual_review_required, or not_applicable"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrMutableSidecarPlan {
    pub collection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub action: DsrMutableSidecarAction,
    pub status: DsrMutableSidecarPlanStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub mutation_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrErasureBlocker {
    pub code: String,
    pub target: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrErasureIdempotencyGuard {
    pub request_id: String,
    pub state_transition: String,
    pub duplicate_completion_behavior: String,
    pub ledger_event_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrErasurePreflight {
    pub dsr_request_id: String,
    pub subject_user_id: String,
    pub assessed_at: String,
    pub assessed_by: String,
    pub status: DsrErasurePreflightStatus,
    pub ledger_event_count_before_completion: usize,
    pub immutable_ledger_blockers: Vec<DsrErasureBlocker>,
    pub mutable_sidecar_plan: Vec<DsrMutableSidecarPlan>,
    pub idempotency_guard: DsrErasureIdempotencyGuard,
    pub destructive_mutation_completed: bool,
    pub full_erasure_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsrRequest {
    pub id: DsrRequestId,
    pub subject_user_id: UserId,
    pub request_type: DsrRequestType,
    pub status: DsrRequestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: String,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DsrExecutionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_notes: Option<String>,
    #[serde(default)]
    pub affected_records: Vec<DsrAffectedRecordSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_review: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis_review: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_preflight: Option<DsrErasurePreflight>,
    /// wp26-gdpr: the dual-control authorization recorded once a distinct approver approves the
    /// destructive erasure plan (bound to the preflight digest). Absent until approved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_authorization: Option<ErasureAuthorization>,
    /// wp26-gdpr: the attestation record written once the destructive erasure executes (the
    /// `subject.erased` event id, techniques applied, erased targets, DEK-destroyed flag). Absent
    /// until executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_execution: Option<ErasureExecutionRecord>,
}

#[derive(Serialize)]
pub struct DsrRequestView {
    pub id: String,
    pub subject_user_id: String,
    pub request_type: DsrRequestType,
    pub status: DsrRequestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DsrExecutionOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_notes: Option<String>,
    pub affected_records: Vec<DsrAffectedRecordSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_review: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_basis_review: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erasure_preflight: Option<DsrErasurePreflight>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erasure_authorization: Option<ErasureAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erasure_execution: Option<ErasureExecutionRecord>,
}

impl From<&DsrRequest> for DsrRequestView {
    fn from(req: &DsrRequest) -> Self {
        Self {
            id: req.id.to_string(),
            subject_user_id: req.subject_user_id.to_string(),
            request_type: req.request_type,
            status: req.status,
            reason: req.reason.clone(),
            created_at: req.created_at.clone(),
            created_by: req.created_by.clone(),
            completed_at: req.completed_at.clone(),
            completed_by: req.completed_by.clone(),
            completion_reason: req.completion_reason.clone(),
            outcome: req.outcome,
            executed_at: req.executed_at.clone(),
            executed_by: req.executed_by.clone(),
            execution_notes: req.execution_notes.clone(),
            affected_records: req.affected_records.clone(),
            retention_review: req.retention_review.clone(),
            legal_basis_review: req.legal_basis_review.clone(),
            erasure_preflight: req.erasure_preflight.clone(),
            erasure_authorization: req.erasure_authorization.clone(),
            erasure_execution: req.erasure_execution.clone(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateDsrRequest {
    #[serde(default, alias = "type")]
    pub request_type: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchDsrRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "completion_reason")]
    pub reason: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub execution_notes: Option<String>,
    #[serde(default)]
    pub affected_records: Option<Vec<DsrAffectedRecordInput>>,
    #[serde(default)]
    pub retention_review: Option<String>,
    #[serde(default)]
    pub legal_basis_review: Option<String>,
    #[serde(default)]
    pub erasure_plan: Option<Vec<DsrMutableSidecarPlanInput>>,
}

#[derive(Default, Deserialize)]
pub struct CompleteDsrRequest {
    #[serde(default, alias = "completion_reason")]
    pub reason: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub execution_notes: Option<String>,
    #[serde(default)]
    pub affected_records: Option<Vec<DsrAffectedRecordInput>>,
    #[serde(default)]
    pub retention_review: Option<String>,
    #[serde(default)]
    pub legal_basis_review: Option<String>,
    #[serde(default)]
    pub erasure_plan: Option<Vec<DsrMutableSidecarPlanInput>>,
}

#[derive(Deserialize)]
pub struct DsrAffectedRecordInput {
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub count: Option<u64>,
}

#[derive(Deserialize)]
pub struct DsrMutableSidecarPlanInput {
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub record_id: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

struct DsrExecutionInput {
    completion_reason: Option<String>,
    outcome: Option<String>,
    execution_notes: Option<String>,
    affected_records: Option<Vec<DsrAffectedRecordInput>>,
    retention_review: Option<String>,
    legal_basis_review: Option<String>,
    erasure_plan: Option<Vec<DsrMutableSidecarPlanInput>>,
}

impl From<CompleteDsrRequest> for DsrExecutionInput {
    fn from(req: CompleteDsrRequest) -> Self {
        Self {
            completion_reason: req.reason,
            outcome: req.outcome,
            execution_notes: req.execution_notes,
            affected_records: req.affected_records,
            retention_review: req.retention_review,
            legal_basis_review: req.legal_basis_review,
            erasure_plan: req.erasure_plan,
        }
    }
}

impl From<PatchDsrRequest> for DsrExecutionInput {
    fn from(req: PatchDsrRequest) -> Self {
        Self {
            completion_reason: req.reason,
            outcome: req.outcome,
            execution_notes: req.execution_notes,
            affected_records: req.affected_records,
            retention_review: req.retention_review,
            legal_basis_review: req.legal_basis_review,
            erasure_plan: req.erasure_plan,
        }
    }
}

struct ValidatedDsrExecution {
    completion_reason: Option<String>,
    outcome: DsrExecutionOutcome,
    execution_notes: Option<String>,
    affected_records: Vec<DsrAffectedRecordSummary>,
    retention_review: Option<String>,
    legal_basis_review: Option<String>,
    erasure_plan: Option<Vec<DsrMutableSidecarPlan>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessorRecordId(pub Uuid);

impl std::fmt::Display for ProcessorRecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DpiaRecordId(pub Uuid);

impl std::fmt::Display for DpiaRecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BreachPlaybookId(pub Uuid);

impl std::fmt::Display for BreachPlaybookId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferControlId(pub Uuid);

impl std::fmt::Display for TransferControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl PrivacyRiskLevel {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(ApiError::Unprocessable(
                "invalid privacy risk_level; expected low, medium, high, or critical".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRecordStatus {
    Draft,
    Active,
    UnderReview,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreachEvidenceKind {
    Review,
    Drill,
}

impl BreachEvidenceKind {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "review" => Ok(Self::Review),
            "drill" => Ok(Self::Drill),
            "completed" | "notified" | "notification" | "incident_closed" => Err(
                ApiError::Unprocessable(
                    "breach evidence records review/drill evidence only; notification or completion claims are not accepted"
                        .to_owned(),
                ),
            ),
            _ => Err(ApiError::Unprocessable(
                "invalid evidence_receipt.evidence_type; expected review or drill".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiaEvidenceKind {
    Review,
    Drill,
}

impl DpiaEvidenceKind {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "review" => Ok(Self::Review),
            "drill" => Ok(Self::Drill),
            "approved" | "accepted" | "filed" | "delivered" | "completed" | "certified" => Err(
                ApiError::Unprocessable(
                    "DPIA evidence records review/drill evidence only; authority filing, legal acceptance, external delivery, completion, or certification claims are not accepted"
                        .to_owned(),
                ),
            ),
            _ => Err(ApiError::Unprocessable(
                "invalid evidence_receipt.evidence_type; expected review or drill".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiaEvidenceReceipt {
    pub id: String,
    pub evidence_type: DpiaEvidenceKind,
    pub recorded_at: String,
    pub recorded_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub authority_filing_completed: bool,
    pub legal_review_accepted: bool,
    pub legal_certification_completed: bool,
    pub external_delivery_completed: bool,
    pub dpia_completed: bool,
    pub compliance_certification_completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachPlaybookEvidenceReceipt {
    pub id: String,
    pub evidence_type: BreachEvidenceKind,
    pub recorded_at: String,
    pub recorded_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub authority_notified: bool,
    pub subjects_notified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferControlEvidenceReceipt {
    pub id: String,
    pub recorded_at: String,
    pub recorded_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub transfer_approved: bool,
    pub data_transfer_executed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAdvisoryReviewStatus {
    NoReceipt,
    Current,
    DueSoon,
    Overdue,
    UnderReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyAdvisoryReviewSummary {
    pub status: PrivacyAdvisoryReviewStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reviewed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_drill_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_review_due_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_until_due: Option<i32>,
    pub review_interval_days: i64,
    pub receipt_count: usize,
    pub review_receipt_count: usize,
    pub drill_receipt_count: usize,
    pub local_advisory_only: bool,
    pub authority_notification_claimed: bool,
    pub subject_notification_claimed: bool,
    pub transfer_approval_claimed: bool,
    pub transfer_execution_claimed: bool,
    pub external_delivery_configured: bool,
    pub legal_completion_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiaAdvisoryReviewSummary {
    #[serde(flatten)]
    pub review: PrivacyAdvisoryReviewSummary,
    pub authority_filing_claimed: bool,
    pub legal_acceptance_claimed: bool,
    pub legal_certification_claimed: bool,
    pub external_delivery_claimed: bool,
    pub completion_claimed: bool,
    pub compliance_certification_claimed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiaTemplateFieldType {
    Text,
    Textarea,
    Checklist,
    Date,
    EvidenceReference,
    ReviewNote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DpiaTemplateChecklistItem {
    pub id: &'static str,
    pub label: &'static str,
    pub field_type: DpiaTemplateFieldType,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DpiaTemplateSection {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub prompts: Vec<&'static str>,
    pub checklist: Vec<DpiaTemplateChecklistItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DpiaTemplateNoClaims {
    pub authority_filing_completed: bool,
    pub authority_approval_obtained: bool,
    pub cnpd_filing_completed: bool,
    pub edpb_filing_completed: bool,
    pub cnpd_or_edpb_approval_obtained: bool,
    pub legal_review_accepted: bool,
    pub legal_validation_completed: bool,
    pub external_validation_completed: bool,
    pub external_legal_validation_completed: bool,
    pub external_delivery_completed: bool,
    pub dpia_completed: bool,
    pub dpia_completion_certified: bool,
    pub compliance_certification_completed: bool,
    pub transfer_approval_claimed: bool,
    pub transfer_execution_claimed: bool,
    pub authority_notification_claimed: bool,
    pub subject_notification_claimed: bool,
    pub automated_risk_scoring_performed: bool,
    pub risk_score_authority_claimed: bool,
    pub automated_legal_decision_made: bool,
    pub register_mutation_performed: bool,
    pub external_call_performed: bool,
    pub raw_register_contents_included: bool,
    pub processor_names_included: bool,
    pub data_subjects_included: bool,
    pub recipients_included: bool,
    pub personal_data_included: bool,
    pub secrets_included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DpiaTemplateView {
    pub schema: &'static str,
    pub template_id: &'static str,
    pub title: &'static str,
    pub version: u32,
    pub language: &'static str,
    pub scope: &'static str,
    pub local_offline_guidance_only: bool,
    pub sections: Vec<DpiaTemplateSection>,
    pub operator_actions: Vec<&'static str>,
    pub no_claims: DpiaTemplateNoClaims,
}

impl PrivacyRecordStatus {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "under_review" => Ok(Self::UnderReview),
            "retired" => Ok(Self::Retired),
            _ => Err(ApiError::Unprocessable(
                "invalid privacy status; expected draft, active, under_review, or retired"
                    .to_owned(),
            )),
        }
    }
}

pub(crate) fn dpia_advisory_review(
    record: &DpiaRecord,
    today: Date,
    due_soon_days: u16,
) -> DpiaAdvisoryReviewSummary {
    let last_reviewed_at = record
        .evidence_receipts
        .iter()
        .filter(|receipt| receipt.evidence_type == DpiaEvidenceKind::Review)
        .filter_map(|receipt| {
            privacy_receipt_sort_key(receipt.occurred_at.as_deref(), &receipt.recorded_at)
        })
        .max_by_key(|(date, _)| *date);
    let last_drill_at = record
        .evidence_receipts
        .iter()
        .filter(|receipt| receipt.evidence_type == DpiaEvidenceKind::Drill)
        .filter_map(|receipt| {
            privacy_receipt_sort_key(receipt.occurred_at.as_deref(), &receipt.recorded_at)
        })
        .max_by_key(|(date, _)| *date);
    let latest_local_evidence = [last_reviewed_at.clone(), last_drill_at.clone()]
        .into_iter()
        .flatten()
        .max_by_key(|(date, _)| *date);

    DpiaAdvisoryReviewSummary {
        review: advisory_review_summary(AdvisoryReviewSummaryInput {
            record_status: record.status,
            latest_local_evidence,
            last_reviewed_at: last_reviewed_at.map(|(_, value)| value),
            last_drill_at: last_drill_at.map(|(_, value)| value),
            today,
            due_soon_days,
            receipt_count: record.evidence_receipts.len(),
            review_receipt_count: record
                .evidence_receipts
                .iter()
                .filter(|receipt| receipt.evidence_type == DpiaEvidenceKind::Review)
                .count(),
            drill_receipt_count: record
                .evidence_receipts
                .iter()
                .filter(|receipt| receipt.evidence_type == DpiaEvidenceKind::Drill)
                .count(),
        }),
        authority_filing_claimed: false,
        legal_acceptance_claimed: false,
        legal_certification_claimed: false,
        external_delivery_claimed: false,
        completion_claimed: false,
        compliance_certification_claimed: false,
    }
}

pub(crate) fn breach_playbook_advisory_review(
    record: &BreachPlaybookRecord,
    today: Date,
    due_soon_days: u16,
) -> PrivacyAdvisoryReviewSummary {
    let last_reviewed_at = record
        .evidence_receipts
        .iter()
        .filter(|receipt| receipt.evidence_type == BreachEvidenceKind::Review)
        .filter_map(|receipt| {
            privacy_receipt_sort_key(receipt.occurred_at.as_deref(), &receipt.recorded_at)
        })
        .max_by_key(|(date, _)| *date);
    let last_drill_at = record
        .evidence_receipts
        .iter()
        .filter(|receipt| receipt.evidence_type == BreachEvidenceKind::Drill)
        .filter_map(|receipt| {
            privacy_receipt_sort_key(receipt.occurred_at.as_deref(), &receipt.recorded_at)
        })
        .max_by_key(|(date, _)| *date);
    let latest_local_evidence = [last_reviewed_at.clone(), last_drill_at.clone()]
        .into_iter()
        .flatten()
        .max_by_key(|(date, _)| *date);

    advisory_review_summary(AdvisoryReviewSummaryInput {
        record_status: record.status,
        latest_local_evidence,
        last_reviewed_at: last_reviewed_at.map(|(_, value)| value),
        last_drill_at: last_drill_at.map(|(_, value)| value),
        today,
        due_soon_days,
        receipt_count: record.evidence_receipts.len(),
        review_receipt_count: record
            .evidence_receipts
            .iter()
            .filter(|receipt| receipt.evidence_type == BreachEvidenceKind::Review)
            .count(),
        drill_receipt_count: record
            .evidence_receipts
            .iter()
            .filter(|receipt| receipt.evidence_type == BreachEvidenceKind::Drill)
            .count(),
    })
}

pub(crate) fn transfer_control_advisory_review(
    record: &TransferControlRecord,
    today: Date,
    due_soon_days: u16,
) -> PrivacyAdvisoryReviewSummary {
    let last_reviewed_at = record
        .evidence_receipts
        .iter()
        .filter_map(|receipt| {
            privacy_receipt_sort_key(receipt.reviewed_at.as_deref(), &receipt.recorded_at)
        })
        .max_by_key(|(date, _)| *date);

    advisory_review_summary(AdvisoryReviewSummaryInput {
        record_status: record.status,
        latest_local_evidence: last_reviewed_at.clone(),
        last_reviewed_at: last_reviewed_at.map(|(_, value)| value),
        last_drill_at: None,
        today,
        due_soon_days,
        receipt_count: record.evidence_receipts.len(),
        review_receipt_count: record.evidence_receipts.len(),
        drill_receipt_count: 0,
    })
}

struct AdvisoryReviewSummaryInput {
    record_status: PrivacyRecordStatus,
    latest_local_evidence: Option<(Date, String)>,
    last_reviewed_at: Option<String>,
    last_drill_at: Option<String>,
    today: Date,
    due_soon_days: u16,
    receipt_count: usize,
    review_receipt_count: usize,
    drill_receipt_count: usize,
}

fn advisory_review_summary(input: AdvisoryReviewSummaryInput) -> PrivacyAdvisoryReviewSummary {
    let AdvisoryReviewSummaryInput {
        record_status,
        latest_local_evidence,
        last_reviewed_at,
        last_drill_at,
        today,
        due_soon_days,
        receipt_count,
        review_receipt_count,
        drill_receipt_count,
    } = input;

    let (status, next_review_due_at, days_until_due) =
        if record_status == PrivacyRecordStatus::UnderReview {
            (PrivacyAdvisoryReviewStatus::UnderReview, None, None)
        } else if let Some((last_date, _)) = latest_local_evidence {
            let next_due_date = last_date + Duration::days(PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS);
            let days = next_due_date.to_julian_day() - today.to_julian_day();
            let status = if days < 0 {
                PrivacyAdvisoryReviewStatus::Overdue
            } else if days <= i32::from(due_soon_days) {
                PrivacyAdvisoryReviewStatus::DueSoon
            } else {
                PrivacyAdvisoryReviewStatus::Current
            };
            (status, Some(format_date(next_due_date)), Some(days))
        } else {
            (PrivacyAdvisoryReviewStatus::NoReceipt, None, None)
        };

    PrivacyAdvisoryReviewSummary {
        status,
        last_reviewed_at,
        last_drill_at,
        next_review_due_at,
        days_until_due,
        review_interval_days: PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS,
        receipt_count,
        review_receipt_count,
        drill_receipt_count,
        local_advisory_only: true,
        authority_notification_claimed: false,
        subject_notification_claimed: false,
        transfer_approval_claimed: false,
        transfer_execution_claimed: false,
        external_delivery_configured: false,
        legal_completion_claimed: false,
    }
}

fn privacy_receipt_sort_key(primary_at: Option<&str>, recorded_at: &str) -> Option<(Date, String)> {
    let selected = primary_at
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(recorded_at);
    parse_privacy_rfc3339_date(selected).map(|date| (date, selected.to_owned()))
}

fn parse_privacy_rfc3339_date(value: &str) -> Option<Date> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|timestamp| timestamp.date())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorRecord {
    pub id: ProcessorRecordId,
    pub name: String,
    pub purpose: String,
    pub legal_basis: String,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub subprocessors: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpiaRecord {
    pub id: DpiaRecordId,
    pub title: String,
    pub purpose: String,
    pub legal_basis: String,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub subprocessors: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    #[serde(default)]
    pub evidence_receipts: Vec<DpiaEvidenceReceipt>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachPlaybookRecord {
    pub id: BreachPlaybookId,
    pub title: String,
    pub scope: String,
    #[serde(default)]
    pub detection_channels: Vec<String>,
    #[serde(default)]
    pub containment_steps: Vec<String>,
    #[serde(default)]
    pub notification_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_notification_window: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_notification_guidance: Option<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipts: Vec<BreachPlaybookEvidenceReceipt>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferControlRecord {
    pub id: TransferControlId,
    pub name: String,
    pub purpose: String,
    pub legal_basis: String,
    #[serde(default)]
    pub data_categories: Vec<String>,
    pub recipient: String,
    pub destination_country: String,
    pub transfer_mechanism: String,
    #[serde(default)]
    pub safeguards: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipts: Vec<TransferControlEvidenceReceipt>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Serialize)]
pub struct ProcessorRecordView {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub legal_basis: String,
    pub data_categories: Vec<String>,
    pub subprocessors: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl From<&ProcessorRecord> for ProcessorRecordView {
    fn from(record: &ProcessorRecord) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.name.clone(),
            purpose: record.purpose.clone(),
            legal_basis: record.legal_basis.clone(),
            data_categories: record.data_categories.clone(),
            subprocessors: record.subprocessors.clone(),
            risk_level: record.risk_level,
            status: record.status,
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct DpiaRecordView {
    pub id: String,
    pub title: String,
    pub purpose: String,
    pub legal_basis: String,
    pub data_categories: Vec<String>,
    pub subprocessors: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    pub evidence_receipts: Vec<DpiaEvidenceReceipt>,
    pub advisory_review: DpiaAdvisoryReviewSummary,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl From<&DpiaRecord> for DpiaRecordView {
    fn from(record: &DpiaRecord) -> Self {
        Self {
            id: record.id.to_string(),
            title: record.title.clone(),
            purpose: record.purpose.clone(),
            legal_basis: record.legal_basis.clone(),
            data_categories: record.data_categories.clone(),
            subprocessors: record.subprocessors.clone(),
            risk_level: record.risk_level,
            status: record.status,
            evidence_receipts: record.evidence_receipts.clone(),
            advisory_review: dpia_advisory_review(record, OffsetDateTime::now_utc().date(), 45),
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
    }
}

fn dpia_template_view() -> DpiaTemplateView {
    use DpiaTemplateFieldType::{Checklist, Date, EvidenceReference, ReviewNote, Text, Textarea};

    let item = |id, label, field_type, required| DpiaTemplateChecklistItem {
        id,
        label,
        field_type,
        required,
    };

    DpiaTemplateView {
        schema: "chancela-privacy-dpia-template/v1",
        template_id: "privacy-dpia-guidance/v1",
        title: "Local DPIA guidance template",
        version: 1,
        language: "en",
        scope: "local_offline_guidance_only",
        local_offline_guidance_only: true,
        sections: vec![
            DpiaTemplateSection {
                id: "processing_description",
                title: "Processing description",
                description: "Capture the proposed processing with placeholders only; do not paste raw register records, subject data, recipients, processor names, or secrets.",
                prompts: vec![
                    "What processing activity is being assessed?",
                    "What purpose and lawful-basis question should a human reviewer consider?",
                    "Which data-category placeholders are in scope?",
                    "Which system or workflow boundary is in scope?",
                ],
                checklist: vec![
                    item("activity_label", "Processing activity label", Text, true),
                    item("purpose_placeholder", "Purpose placeholder", Textarea, true),
                    item(
                        "lawful_basis_prompt",
                        "Lawful-basis review prompt",
                        Textarea,
                        true,
                    ),
                    item(
                        "data_category_placeholders",
                        "Data-category placeholders",
                        Checklist,
                        true,
                    ),
                    item(
                        "system_boundary",
                        "System/workflow boundary",
                        Textarea,
                        false,
                    ),
                ],
            },
            DpiaTemplateSection {
                id: "necessity_proportionality",
                title: "Necessity and proportionality prompts",
                description: "Guide a human review of necessity, minimization, retention, and alternatives without deciding legal sufficiency.",
                prompts: vec![
                    "Why is this processing necessary for the stated purpose?",
                    "What lower-impact alternatives should be considered?",
                    "What minimization or retention constraints should be reviewed?",
                    "What transparency or operator-facing notice gaps should be checked?",
                ],
                checklist: vec![
                    item(
                        "necessity_rationale",
                        "Necessity rationale prompt",
                        Textarea,
                        true,
                    ),
                    item(
                        "less_intrusive_alternatives",
                        "Alternatives to consider",
                        Checklist,
                        true,
                    ),
                    item(
                        "minimization_controls",
                        "Minimization controls to review",
                        Checklist,
                        true,
                    ),
                    item(
                        "retention_prompt",
                        "Retention review prompt",
                        Textarea,
                        false,
                    ),
                    item(
                        "transparency_prompt",
                        "Transparency review prompt",
                        Textarea,
                        false,
                    ),
                ],
            },
            DpiaTemplateSection {
                id: "risk_prompts",
                title: "Risk prompts",
                description: "Collect qualitative risk prompts only; this template does not calculate, rank, or authorize risk.",
                prompts: vec![
                    "What rights-and-freedoms impacts should be reviewed?",
                    "What confidentiality, integrity, availability, or misuse scenarios should be considered?",
                    "What vulnerable-context or scale factors need human attention?",
                    "What unresolved questions require escalation?",
                ],
                checklist: vec![
                    item("rights_impacts", "Rights-impact prompts", Checklist, true),
                    item(
                        "misuse_scenarios",
                        "Misuse or confidentiality scenarios",
                        Checklist,
                        true,
                    ),
                    item(
                        "scale_context",
                        "Scale/context review prompt",
                        Textarea,
                        false,
                    ),
                    item(
                        "unresolved_questions",
                        "Unresolved questions",
                        Checklist,
                        false,
                    ),
                    item(
                        "risk_review_note",
                        "Human risk review note",
                        ReviewNote,
                        false,
                    ),
                ],
            },
            DpiaTemplateSection {
                id: "safeguards",
                title: "Safeguards",
                description: "List safeguards and evidence references for later human review; do not treat the list as certification or approval.",
                prompts: vec![
                    "Which technical and organizational safeguards should be evidenced?",
                    "Which access-control, logging, retention, and security controls need review?",
                    "Which residual safeguards need owner follow-up?",
                ],
                checklist: vec![
                    item(
                        "technical_safeguards",
                        "Technical safeguards",
                        Checklist,
                        true,
                    ),
                    item(
                        "organizational_safeguards",
                        "Organizational safeguards",
                        Checklist,
                        true,
                    ),
                    item(
                        "access_logging_controls",
                        "Access/logging controls",
                        Checklist,
                        false,
                    ),
                    item(
                        "evidence_references",
                        "Local evidence references",
                        EvidenceReference,
                        false,
                    ),
                    item(
                        "residual_follow_up",
                        "Residual follow-up items",
                        Checklist,
                        false,
                    ),
                ],
            },
            DpiaTemplateSection {
                id: "consultation_escalation",
                title: "Consultation and escalation prompts",
                description: "Record prompts for operator escalation decisions without claiming consultation occurred or authority approval was obtained.",
                prompts: vec![
                    "Which internal reviewer roles should inspect this DPIA?",
                    "What consultation or escalation question remains open?",
                    "What blocker prevents treating this as reviewed?",
                    "What next operator action should be recorded outside this template?",
                ],
                checklist: vec![
                    item(
                        "reviewer_roles",
                        "Reviewer role placeholders",
                        Checklist,
                        false,
                    ),
                    item(
                        "consultation_questions",
                        "Consultation questions",
                        Checklist,
                        false,
                    ),
                    item(
                        "escalation_blockers",
                        "Escalation blockers",
                        Checklist,
                        false,
                    ),
                    item(
                        "target_review_date",
                        "Target local review date",
                        Date,
                        false,
                    ),
                    item(
                        "next_operator_action",
                        "Next operator action",
                        ReviewNote,
                        true,
                    ),
                ],
            },
            DpiaTemplateSection {
                id: "evidence_boundaries",
                title: "Evidence and no-claim boundaries",
                description: "Preserve the local/offline boundary and false no-claim flags when this template is exported, copied, or used for operator review.",
                prompts: vec![
                    "Which local evidence references support the prompts?",
                    "Which authority, legal, external-validation, scoring, completion, and register-mutation claims remain false?",
                    "What must be reviewed before any separate record is updated?",
                ],
                checklist: vec![
                    item(
                        "local_evidence_index",
                        "Local evidence index placeholders",
                        EvidenceReference,
                        false,
                    ),
                    item(
                        "false_no_claim_flags",
                        "False no-claim flags acknowledged",
                        Checklist,
                        true,
                    ),
                    item(
                        "no_sensitive_echo_check",
                        "No sensitive/register echo check",
                        Checklist,
                        true,
                    ),
                    item(
                        "separate_record_update_prompt",
                        "Separate register update prompt",
                        ReviewNote,
                        false,
                    ),
                ],
            },
        ],
        operator_actions: vec![
            "Fill placeholders locally with human-authored notes outside this template response.",
            "Review necessity, proportionality, risks, safeguards, and escalation questions before any separate DPIA register update.",
            "Keep authority filing, legal acceptance, external validation, automated scoring, completion, certification, and register-mutation claims false unless separately evidenced outside this template.",
            "Do not paste personal data, secrets, raw register contents, processor names, data subjects, or recipients into the template response.",
        ],
        no_claims: DpiaTemplateNoClaims {
            authority_filing_completed: false,
            authority_approval_obtained: false,
            cnpd_filing_completed: false,
            edpb_filing_completed: false,
            cnpd_or_edpb_approval_obtained: false,
            legal_review_accepted: false,
            legal_validation_completed: false,
            external_validation_completed: false,
            external_legal_validation_completed: false,
            external_delivery_completed: false,
            dpia_completed: false,
            dpia_completion_certified: false,
            compliance_certification_completed: false,
            transfer_approval_claimed: false,
            transfer_execution_claimed: false,
            authority_notification_claimed: false,
            subject_notification_claimed: false,
            automated_risk_scoring_performed: false,
            risk_score_authority_claimed: false,
            automated_legal_decision_made: false,
            register_mutation_performed: false,
            external_call_performed: false,
            raw_register_contents_included: false,
            processor_names_included: false,
            data_subjects_included: false,
            recipients_included: false,
            personal_data_included: false,
            secrets_included: false,
        },
    }
}

#[derive(Serialize)]
pub struct BreachPlaybookView {
    pub id: String,
    pub title: String,
    pub scope: String,
    pub detection_channels: Vec<String>,
    pub containment_steps: Vec<String>,
    pub notification_roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_notification_window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_notification_guidance: Option<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    pub evidence_receipts: Vec<BreachPlaybookEvidenceReceipt>,
    pub advisory_review: PrivacyAdvisoryReviewSummary,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl From<&BreachPlaybookRecord> for BreachPlaybookView {
    fn from(record: &BreachPlaybookRecord) -> Self {
        Self {
            id: record.id.to_string(),
            title: record.title.clone(),
            scope: record.scope.clone(),
            detection_channels: record.detection_channels.clone(),
            containment_steps: record.containment_steps.clone(),
            notification_roles: record.notification_roles.clone(),
            authority_notification_window: record.authority_notification_window.clone(),
            subject_notification_guidance: record.subject_notification_guidance.clone(),
            risk_level: record.risk_level,
            status: record.status,
            review_notes: record.review_notes.clone(),
            evidence_receipts: record.evidence_receipts.clone(),
            advisory_review: breach_playbook_advisory_review(
                record,
                OffsetDateTime::now_utc().date(),
                45,
            ),
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct TransferControlView {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub legal_basis: String,
    pub data_categories: Vec<String>,
    pub recipient: String,
    pub destination_country: String,
    pub transfer_mechanism: String,
    pub safeguards: Vec<String>,
    pub risk_level: PrivacyRiskLevel,
    pub status: PrivacyRecordStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    pub evidence_receipts: Vec<TransferControlEvidenceReceipt>,
    pub advisory_review: PrivacyAdvisoryReviewSummary,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl From<&TransferControlRecord> for TransferControlView {
    fn from(record: &TransferControlRecord) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.name.clone(),
            purpose: record.purpose.clone(),
            legal_basis: record.legal_basis.clone(),
            data_categories: record.data_categories.clone(),
            recipient: record.recipient.clone(),
            destination_country: record.destination_country.clone(),
            transfer_mechanism: record.transfer_mechanism.clone(),
            safeguards: record.safeguards.clone(),
            risk_level: record.risk_level,
            status: record.status,
            review_notes: record.review_notes.clone(),
            evidence_receipts: record.evidence_receipts.clone(),
            advisory_review: transfer_control_advisory_review(
                record,
                OffsetDateTime::now_utc().date(),
                45,
            ),
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateProcessorRecord {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub subprocessors: Vec<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchProcessorRecord {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Option<Vec<String>>,
    #[serde(default)]
    pub subprocessors: Option<Vec<String>>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateDpiaRecord {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub subprocessors: Vec<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<DpiaEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct PatchDpiaRecord {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Option<Vec<String>>,
    #[serde(default)]
    pub subprocessors: Option<Vec<String>>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<DpiaEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct CreateBreachPlaybook {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub detection_channels: Vec<String>,
    #[serde(default)]
    pub containment_steps: Vec<String>,
    #[serde(default)]
    pub notification_roles: Vec<String>,
    #[serde(default)]
    pub authority_notification_window: Option<String>,
    #[serde(default)]
    pub subject_notification_guidance: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<BreachEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct PatchBreachPlaybook {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub detection_channels: Option<Vec<String>>,
    #[serde(default)]
    pub containment_steps: Option<Vec<String>>,
    #[serde(default)]
    pub notification_roles: Option<Vec<String>>,
    #[serde(default)]
    pub authority_notification_window: Option<String>,
    #[serde(default)]
    pub subject_notification_guidance: Option<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<BreachEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct CreateTransferControl {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Vec<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub destination_country: Option<String>,
    #[serde(default)]
    pub transfer_mechanism: Option<String>,
    #[serde(default)]
    pub safeguards: Vec<String>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<TransferEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct PatchTransferControl {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub data_categories: Option<Vec<String>>,
    #[serde(default)]
    pub recipient: Option<String>,
    #[serde(default)]
    pub destination_country: Option<String>,
    #[serde(default)]
    pub transfer_mechanism: Option<String>,
    #[serde(default)]
    pub safeguards: Option<Vec<String>>,
    #[serde(default)]
    pub risk_level: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub review_notes: Option<String>,
    #[serde(default)]
    pub evidence_receipt: Option<TransferEvidenceReceiptInput>,
}

#[derive(Deserialize)]
pub struct BreachEvidenceReceiptInput {
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub occurred_at: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub authority_notified: Option<bool>,
    #[serde(default)]
    pub subjects_notified: Option<bool>,
    #[serde(default)]
    pub notification_completed: Option<bool>,
    #[serde(default)]
    pub incident_closed: Option<bool>,
}

#[derive(Deserialize)]
pub struct TransferEvidenceReceiptInput {
    #[serde(default)]
    pub reviewed_at: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub transfer_approved: Option<bool>,
    #[serde(default)]
    pub data_transfer_executed: Option<bool>,
    #[serde(default)]
    pub legal_certification_completed: Option<bool>,
}

#[derive(Deserialize)]
pub struct DpiaEvidenceReceiptInput {
    #[serde(default)]
    pub evidence_type: Option<String>,
    #[serde(default)]
    pub occurred_at: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub authority_filing_completed: Option<bool>,
    #[serde(default)]
    pub legal_review_accepted: Option<bool>,
    #[serde(default)]
    pub legal_certification_completed: Option<bool>,
    #[serde(default)]
    pub external_delivery_completed: Option<bool>,
    #[serde(default)]
    pub dpia_completed: Option<bool>,
    #[serde(default)]
    pub compliance_certification_completed: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RetentionPolicyId(pub Uuid);

impl std::fmt::Display for RetentionPolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicyStatus {
    Draft,
    Active,
    Suspended,
    Retired,
}

impl RetentionPolicyStatus {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "draft" => Ok(Self::Draft),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "retired" => Ok(Self::Retired),
            _ => Err(ApiError::Unprocessable(
                "invalid retention policy status; expected draft, active, suspended, or retired"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionDisposalAction {
    Review,
    Archive,
    Anonymize,
    Delete,
    LegalHold,
    NoAction,
}

impl RetentionDisposalAction {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "review" => Ok(Self::Review),
            "archive" => Ok(Self::Archive),
            "anonymize" | "anonymise" => Ok(Self::Anonymize),
            "delete" => Ok(Self::Delete),
            "legal_hold" => Ok(Self::LegalHold),
            "no_action" | "none" => Ok(Self::NoAction),
            _ => Err(ApiError::Unprocessable(
                "invalid disposal_action; expected review, archive, anonymize, delete, legal_hold, or no_action"
                    .to_owned(),
            )),
        }
    }

    fn is_destructive(self) -> bool {
        matches!(self, Self::Delete | Self::Anonymize)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Archive => "archive",
            Self::Anonymize => "anonymize",
            Self::Delete => "delete",
            Self::LegalHold => "legal_hold",
            Self::NoAction => "no_action",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicyRecord {
    pub id: RetentionPolicyId,
    pub name: String,
    pub scope: String,
    pub category: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub legal_basis: String,
    pub disposal_action: RetentionDisposalAction,
    pub status: RetentionPolicyStatus,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

#[derive(Serialize)]
pub struct RetentionPolicyView {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub category: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub legal_basis: String,
    pub disposal_action: RetentionDisposalAction,
    pub status: RetentionPolicyStatus,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}

impl From<&RetentionPolicyRecord> for RetentionPolicyView {
    fn from(record: &RetentionPolicyRecord) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.name.clone(),
            scope: record.scope.clone(),
            category: record.category.clone(),
            schedule_id: record.schedule_id.clone(),
            retention_period: record.retention_period.clone(),
            legal_basis: record.legal_basis.clone(),
            disposal_action: record.disposal_action,
            status: record.status,
            active: record.active,
            notes: record.notes.clone(),
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRetentionPolicy {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub schedule_id: Option<String>,
    #[serde(default)]
    pub retention_period: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub disposal_action: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchRetentionPolicy {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub schedule_id: Option<String>,
    #[serde(default)]
    pub retention_period: Option<String>,
    #[serde(default)]
    pub legal_basis: Option<String>,
    #[serde(default)]
    pub disposal_action: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct RetentionDryRunRequest {
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub record_id: Option<String>,
    #[serde(default)]
    pub execution_request: Option<RetentionExecutionRequest>,
}

#[derive(Deserialize)]
pub struct RetentionExecutionRequest {
    #[serde(default)]
    pub requested_policy_id: Option<String>,
    #[serde(default)]
    pub execution_mode: Option<String>,
    #[serde(default)]
    pub operator_notes: Option<String>,
    #[serde(default)]
    pub evidence: Option<Vec<RetentionExecutionEvidenceInput>>,
    #[serde(default)]
    pub approval: Option<RetentionExecutionApprovalInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReviewClosureRequest {
    #[serde(default, alias = "operator_decision")]
    pub review_closure_decision: Option<String>,
    #[serde(default, alias = "closure_evidence")]
    pub review_closure_evidence: Option<Vec<RetentionReviewClosureEvidenceInput>>,
    #[serde(default, alias = "closure_note")]
    pub review_closure_note: Option<String>,
    #[serde(default)]
    pub destructive_disposal_completed: Option<bool>,
    #[serde(default)]
    pub full_erasure_completed: Option<bool>,
    #[serde(default)]
    pub legal_hold_mutated: Option<bool>,
    #[serde(default)]
    pub retention_policy_mutated: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionCandidateResolutionRequest {
    #[serde(default)]
    pub candidate_fingerprint: Option<String>,
    #[serde(default, alias = "resolution_disposition")]
    pub disposition: Option<String>,
    #[serde(default, alias = "resolution_note")]
    pub note: Option<String>,
    #[serde(default, alias = "resolution_evidence")]
    pub evidence: Option<Vec<RetentionReviewClosureEvidenceInput>>,
    #[serde(default)]
    pub destructive_disposal_completed: Option<bool>,
    #[serde(default)]
    pub disposal_completed: Option<bool>,
    #[serde(default)]
    pub full_erasure_completed: Option<bool>,
    #[serde(default)]
    pub erasure_completed: Option<bool>,
    #[serde(default)]
    pub legal_hold_mutated: Option<bool>,
    #[serde(default)]
    pub legal_hold_resolved: Option<bool>,
    #[serde(default)]
    pub retention_policy_mutated: Option<bool>,
    #[serde(default)]
    pub retention_policy_changed: Option<bool>,
    #[serde(default)]
    pub legal_completion_claimed: Option<bool>,
    #[serde(default)]
    pub legal_disposal_completed: Option<bool>,
}

#[derive(Deserialize)]
pub struct RetentionExecutionApprovalInput {
    #[serde(default)]
    pub approval_reference: Option<String>,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub disposal_action: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approved_at: Option<String>,
}

#[derive(Deserialize)]
pub struct RetentionExecutionEvidenceInput {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReviewClosureEvidenceInput {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Serialize)]
pub struct RetentionDryRunReport {
    pub mode: &'static str,
    pub execution_supported: bool,
    pub destructive_execution_supported: bool,
    pub candidate: RetentionDryRunCandidate,
    pub matched_count: usize,
    pub matches: Vec<RetentionDryRunMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_record: Option<RetentionExecutionRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionDryRunCandidate {
    pub scope: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
}

#[derive(Serialize)]
pub struct RetentionDryRunMatch {
    pub policy_id: String,
    pub name: String,
    pub scope: String,
    pub category: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub disposal_action: RetentionDisposalAction,
    pub status: RetentionPolicyStatus,
    pub active: bool,
    pub destructive_action: bool,
    pub would_execute: bool,
    pub reason: &'static str,
}

#[derive(Serialize)]
pub struct RetentionDueCandidatesReport {
    pub generated_at: String,
    pub scope: &'static str,
    pub category: &'static str,
    pub candidate_count: usize,
    pub suppressed_candidate_count: usize,
    pub suppressed_by_bounded_evidence_count: usize,
    pub candidate_resolution_record_count: usize,
    pub candidates_with_resolution_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_summary: Option<RetentionDueCandidatesSuppressionSummary>,
    pub candidates: Vec<RetentionDueCandidate>,
}

#[derive(Serialize)]
pub struct RetentionDueCandidatesSuppressionSummary {
    pub suppressed_by_bounded_evidence_count: usize,
    pub note: &'static str,
}

#[derive(Serialize)]
pub struct RetentionDueCandidate {
    pub candidate_id: String,
    pub candidate_fingerprint: String,
    pub scope: String,
    pub category: String,
    pub record_id: String,
    pub book_id: String,
    pub entity_id: String,
    pub closing_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    pub overdue: bool,
    pub policy_id: String,
    pub policy_name: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub disposal_action: RetentionDisposalAction,
    pub destructive_action: bool,
    pub legal_hold_blockers: Vec<RetentionDueLegalHoldBlocker>,
    pub required_approvals: Vec<RetentionRequiredApproval>,
    pub blockers: Vec<RetentionWorkflowBlocker>,
    pub findings: Vec<RetentionDueFinding>,
    pub outcome: String,
    pub status: String,
    pub candidate_evidence_state: RetentionEvidenceState,
    pub evidence_next_step: String,
    pub would_execute: bool,
    pub destructive_disposal_completed: bool,
    pub full_erasure_completed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_execution: Option<RetentionDueCandidatePriorExecution>,
    pub candidate_resolution_record_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_resolution: Option<RetentionCandidateResolutionSummary>,
    pub next_step: String,
}

#[derive(Serialize)]
pub struct RetentionDueCandidatePriorExecution {
    pub execution_id: String,
    pub execution_status: String,
    pub outcome: String,
    pub evidence_state: RetentionEvidenceState,
    pub evidence_next_step: String,
    pub requested_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
    pub bounded_executor: bool,
    pub targets_acted_count: usize,
    pub destructive_disposal_completed: bool,
    pub full_erasure_completed: bool,
    pub next_step: String,
}

#[derive(Clone, Serialize)]
pub struct RetentionDueLegalHoldBlocker {
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_period: Option<String>,
    pub reason: String,
}

#[derive(Clone, Serialize)]
pub struct RetentionDueFinding {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Debug)]
struct ValidatedRetentionExecutionRequest {
    requested_policy_id: Option<RetentionPolicyId>,
    execution_intent: RetentionExecutionIntent,
    operator_notes: Option<String>,
    evidence: Vec<RetentionOperatorEvidence>,
    approval: Option<RetentionExecutionApproval>,
}

#[derive(Debug)]
struct ValidatedRetentionReviewClosure {
    decision: RetentionReviewClosureDecision,
    note: Option<String>,
    evidence: Vec<RetentionOperatorEvidence>,
}

#[derive(Debug)]
struct ValidatedRetentionCandidateResolution {
    disposition: RetentionCandidateDisposition,
    note: Option<String>,
    evidence: Vec<RetentionOperatorEvidence>,
}

#[derive(Default, Deserialize)]
pub(crate) struct RetentionExecutionListQuery {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionCandidateDisposition {
    EvidenceAcknowledged,
    FollowUpRequired,
    BlockedFollowUp,
}

impl RetentionCandidateDisposition {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "evidence_acknowledged" => Ok(Self::EvidenceAcknowledged),
            "follow_up_required" | "followup_required" => Ok(Self::FollowUpRequired),
            "blocked_follow_up" | "blocked_followup" => Ok(Self::BlockedFollowUp),
            _ => Err(ApiError::Unprocessable(
                "invalid disposition; expected evidence_acknowledged, follow_up_required, or blocked_follow_up"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionCandidateResolutionRecord {
    pub id: String,
    pub candidate_id: String,
    pub candidate_fingerprint: String,
    pub recorded_at: String,
    pub recorded_by: String,
    pub disposition: RetentionCandidateDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub evidence: Vec<RetentionOperatorEvidence>,
    pub evidence_count: usize,
    pub candidate: RetentionCandidateResolutionSnapshot,
    pub evidence_only: bool,
    pub destructive_disposal_completed: bool,
    pub disposal_completed: bool,
    pub full_erasure_completed: bool,
    pub erasure_completed: bool,
    pub legal_hold_mutated: bool,
    pub legal_hold_resolved: bool,
    pub retention_policy_mutated: bool,
    pub retention_policy_changed: bool,
    pub legal_completion_claimed: bool,
    pub legal_disposal_completed: bool,
    pub next_step: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionCandidateResolutionSnapshot {
    pub candidate_id: String,
    pub candidate_fingerprint: String,
    pub scope: String,
    pub category: String,
    pub record_id: String,
    pub book_id: String,
    pub entity_id: String,
    pub closing_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    pub overdue: bool,
    pub policy_id: String,
    pub policy_name: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub disposal_action: RetentionDisposalAction,
    pub destructive_action: bool,
    pub outcome: String,
    pub status: String,
    pub candidate_evidence_state: RetentionEvidenceState,
    pub legal_hold_blocker_count: usize,
    pub required_approval_count: usize,
    pub blocker_count: usize,
    pub finding_count: usize,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionCandidateResolutionSummary {
    pub id: String,
    pub candidate_fingerprint: String,
    pub recorded_at: String,
    pub recorded_by: String,
    pub disposition: RetentionCandidateDisposition,
    pub evidence_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub evidence_only: bool,
    pub destructive_disposal_completed: bool,
    pub disposal_completed: bool,
    pub full_erasure_completed: bool,
    pub erasure_completed: bool,
    pub legal_hold_mutated: bool,
    pub legal_hold_resolved: bool,
    pub retention_policy_mutated: bool,
    pub retention_policy_changed: bool,
    pub legal_completion_claimed: bool,
    pub legal_disposal_completed: bool,
    pub next_step: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionExecutionRecord {
    pub id: String,
    pub requested_at: String,
    pub actor: String,
    #[serde(default = "default_retention_execution_intent")]
    pub execution_intent: RetentionExecutionIntent,
    #[serde(default = "default_retention_execution_status")]
    pub execution_status: RetentionExecutionStatus,
    #[serde(default = "default_retention_operator_review_decision")]
    pub operator_review_decision: RetentionOperatorReviewDecision,
    #[serde(default = "default_retention_execution_decision_state")]
    pub decision_state: RetentionExecutionDecisionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_closure_decision: Option<RetentionReviewClosureDecision>,
    #[serde(default)]
    pub review_closure_evidence: Vec<RetentionOperatorEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_closed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_closed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_closure_note: Option<String>,
    #[serde(default)]
    pub destructive_disposal_completed: bool,
    #[serde(default)]
    pub full_erasure_completed: bool,
    #[serde(default)]
    pub legal_hold_mutated: bool,
    #[serde(default)]
    pub retention_policy_mutated: bool,
    pub requested_policy: RetentionExecutionRequestedPolicy,
    pub candidate: RetentionDryRunCandidate,
    pub matched_records_summary: RetentionMatchedRecordsSummary,
    pub legal_hold_blockers: Vec<RetentionLegalHoldBlocker>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_notes: Option<String>,
    #[serde(default)]
    #[serde(rename = "audit_evidence", alias = "operator_evidence")]
    pub audit_evidence: Vec<RetentionOperatorEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<RetentionExecutionApproval>,
    pub outcome: RetentionExecutionOutcome,
    pub block_reason: String,
    #[serde(default = "default_retention_evidence_state")]
    pub evidence_state: RetentionEvidenceState,
    #[serde(default)]
    pub evidence_next_step: String,
    #[serde(default = "legacy_retention_operator_workflow")]
    pub workflow: RetentionOperatorWorkflow,
    #[serde(default = "legacy_retention_execution_result")]
    pub execution_result: RetentionExecutionResult,
    pub would_execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionExecutionIntent {
    ReviewOnly,
    ExecuteSupported,
}

impl RetentionExecutionIntent {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "review_only" => Ok(Self::ReviewOnly),
            "execute_supported" | "execute" => Ok(Self::ExecuteSupported),
            _ => Err(ApiError::Unprocessable(
                "invalid execution_request.execution_mode; expected review_only or execute_supported"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionExecutionStatus {
    AwaitingReview,
    Blocked,
    Executed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionOperatorReviewDecision {
    ReviewRequired,
    Blocked,
    ExecutionRecorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionExecutionDecisionState {
    Open,
    ReviewClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
// Variants intentionally share the `EvidenceAcknowledged` suffix: it is the serde
// snake_case wire contract for the acknowledgement, and renaming would change the payload format.
#[allow(clippy::enum_variant_names)]
pub enum RetentionReviewClosureDecision {
    ReviewEvidenceAcknowledged,
    BoundedEvidenceAcknowledged,
    BlockedEvidenceAcknowledged,
}

impl RetentionReviewClosureDecision {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match normalize_enum(raw).as_str() {
            "review_evidence_acknowledged" => Ok(Self::ReviewEvidenceAcknowledged),
            "bounded_evidence_acknowledged" => Ok(Self::BoundedEvidenceAcknowledged),
            "blocked_evidence_acknowledged" => Ok(Self::BlockedEvidenceAcknowledged),
            _ => Err(ApiError::Unprocessable(
                "invalid review_closure_decision; expected review_evidence_acknowledged, bounded_evidence_acknowledged, or blocked_evidence_acknowledged"
                    .to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionEvidenceState {
    ReviewQueued,
    Blocked,
    BoundedArchiveRecorded,
    BoundedNoActionRecorded,
    PriorBoundedEvidenceAvailable,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionExecutionRequestedPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposal_action: Option<RetentionDisposalAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<RetentionPolicyStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    pub stale: bool,
    pub matches_candidate: bool,
    pub destructive_action: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionMatchedRecordsSummary {
    pub scope: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    pub record_count: usize,
    pub policy_match_count: usize,
    pub destructive_policy_count: usize,
    pub policy_ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionLegalHoldBlocker {
    pub policy_id: String,
    pub name: String,
    pub schedule_id: String,
    pub retention_period: String,
    pub reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionOperatorWorkflow {
    pub status: RetentionOperatorWorkflowStatus,
    pub blockers: Vec<RetentionWorkflowBlocker>,
    pub required_approvals: Vec<RetentionRequiredApproval>,
    pub next_step: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionOperatorWorkflowStatus {
    Blocked,
    AwaitingManualReview,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionWorkflowBlocker {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionRequiredApproval {
    pub code: String,
    pub required_from: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionOperatorEvidence {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RetentionExecutionApproval {
    pub approval_reference: String,
    pub policy_id: String,
    pub disposal_action: RetentionDisposalAction,
    pub approved_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionExecutionResult {
    pub bounded_executor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    pub targets_considered: Vec<RetentionExecutionTargetEvidence>,
    pub targets_acted: Vec<RetentionExecutionTargetEvidence>,
    pub targets_skipped: Vec<RetentionExecutionTargetEvidence>,
    pub reason_codes: Vec<String>,
    pub next_step: String,
    pub destructive_disposal_completed: bool,
    pub full_erasure_completed: bool,
    #[serde(default)]
    pub blocker_metadata: Vec<RetentionExecutionBlockerMetadata>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionExecutionTargetEvidence {
    pub target_type: String,
    pub target_id: String,
    pub action: String,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionExecutionBlockerMetadata {
    pub code: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
}

#[derive(Serialize)]
struct RetentionReviewClosureLedgerEvent<'a> {
    execution_id: &'a str,
    decision_state: RetentionExecutionDecisionState,
    review_closure_decision: Option<RetentionReviewClosureDecision>,
    review_closure_evidence: &'a [RetentionOperatorEvidence],
    review_closed_by: Option<&'a str>,
    review_closed_at: Option<&'a str>,
    review_closure_note: Option<&'a str>,
    destructive_disposal_completed: bool,
    full_erasure_completed: bool,
    legal_hold_mutated: bool,
    retention_policy_mutated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionExecutionOutcome {
    BlockedMissingPolicy,
    BlockedStalePolicy,
    BlockedPolicyMismatch,
    BlockedLegalHold,
    BlockedDestructiveAction,
    BlockedApprovalMismatch,
    BlockedMissingTarget,
    ManualReviewRequired,
    BoundedArchiveRecorded,
    BoundedNoActionRecorded,
    AlreadyExecuted,
}

pub(crate) fn load_dsr_requests(path: &FsPath) -> Option<HashMap<DsrRequestId, DsrRequest>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<serde_json::Value>>(&bytes) {
        Ok(list) => {
            let mut loaded = HashMap::new();
            for (idx, value) in list.into_iter().enumerate() {
                match serde_json::from_value::<DsrRequest>(value) {
                    Ok(request) => {
                        loaded.insert(request.id, request);
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: {} has an invalid privacy DSR request at index {idx} ({e}); ignoring it",
                            path.display()
                        );
                    }
                }
            }
            Some(loaded)
        }
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid privacy DSR request document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_processor_records(
    path: &FsPath,
) -> Option<HashMap<ProcessorRecordId, ProcessorRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<ProcessorRecord>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|record| (record.id, record)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid privacy processor document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_dpia_records(path: &FsPath) -> Option<HashMap<DpiaRecordId, DpiaRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<DpiaRecord>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|record| (record.id, record)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid privacy DPIA document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_breach_playbooks(
    path: &FsPath,
) -> Option<HashMap<BreachPlaybookId, BreachPlaybookRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<BreachPlaybookRecord>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|record| (record.id, record)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid privacy breach playbook document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_transfer_controls(
    path: &FsPath,
) -> Option<HashMap<TransferControlId, TransferControlRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<TransferControlRecord>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|record| (record.id, record)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid privacy transfer control document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_retention_policies(
    path: &FsPath,
) -> Option<HashMap<RetentionPolicyId, RetentionPolicyRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<RetentionPolicyRecord>>(&bytes) {
        Ok(list) => Some(list.into_iter().map(|record| (record.id, record)).collect()),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid retention policy document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_retention_execution_records(
    path: &FsPath,
) -> Option<HashMap<String, RetentionExecutionRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<RetentionExecutionRecord>>(&bytes) {
        Ok(list) => Some(
            list.into_iter()
                .map(|mut record| {
                    normalize_retention_execution_record(&mut record);
                    (record.id.clone(), record)
                })
                .collect(),
        ),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid retention execution document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn load_retention_candidate_resolution_records(
    path: &FsPath,
) -> Option<HashMap<String, RetentionCandidateResolutionRecord>> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Vec<RetentionCandidateResolutionRecord>>(&bytes) {
        Ok(list) => Some(
            list.into_iter()
                .map(|record| (record.id.clone(), record))
                .collect(),
        ),
        Err(e) => {
            eprintln!(
                "warning: {} is not a valid retention candidate resolution document ({e}); ignoring it",
                path.display()
            );
            None
        }
    }
}

pub(crate) fn write_dsr_requests_atomic(
    path: &FsPath,
    requests: &HashMap<DsrRequestId, DsrRequest>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&DsrRequest> = requests.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, DSR_REQUESTS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_processor_records_atomic(
    path: &FsPath,
    records: &HashMap<ProcessorRecordId, ProcessorRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&ProcessorRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, PROCESSORS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_dpia_records_atomic(
    path: &FsPath,
    records: &HashMap<DpiaRecordId, DpiaRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&DpiaRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, DPIAS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_breach_playbooks_atomic(
    path: &FsPath,
    records: &HashMap<BreachPlaybookId, BreachPlaybookRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&BreachPlaybookRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, BREACH_PLAYBOOKS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_transfer_controls_atomic(
    path: &FsPath,
    records: &HashMap<TransferControlId, TransferControlRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&TransferControlRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, TRANSFER_CONTROLS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_retention_policies_atomic(
    path: &FsPath,
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&RetentionPolicyRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, RETENTION_POLICIES_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_retention_execution_records_atomic(
    path: &FsPath,
    records: &HashMap<String, RetentionExecutionRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&RetentionExecutionRecord> = records.values().collect();
    list.sort_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, RETENTION_EXECUTIONS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn write_retention_candidate_resolution_records_atomic(
    path: &FsPath,
    records: &HashMap<String, RetentionCandidateResolutionRecord>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut list: Vec<&RetentionCandidateResolutionRecord> = records.values().collect();
    list.sort_by(|a, b| a.recorded_at.cmp(&b.recorded_at).then(a.id.cmp(&b.id)));
    let json = serde_json::to_vec_pretty(&list).map_err(std::io::Error::other)?;
    let tmp = tmp_path(path, RETENTION_CANDIDATE_RESOLUTIONS_FILE);
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn tmp_path(path: &FsPath, fallback: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| fallback.into());
    name.push(format!(".{}.tmp", Uuid::new_v4()));
    path.with_file_name(name)
}

async fn persist_dsr_requests(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.dsr_requests_path {
        let requests = state.dsr_requests.read().await;
        write_dsr_requests_atomic(path, &requests)
            .map_err(|e| ApiError::Internal(format!("failed to persist DSR requests: {e}")))?;
    }
    Ok(())
}

async fn persist_processor_records(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.processor_records_path {
        let records = state.processor_records.read().await;
        write_processor_records_atomic(path, &records)
            .map_err(|e| ApiError::Internal(format!("failed to persist processor records: {e}")))?;
    }
    Ok(())
}

async fn persist_dpia_records(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.dpia_records_path {
        let records = state.dpia_records.read().await;
        write_dpia_records_atomic(path, &records)
            .map_err(|e| ApiError::Internal(format!("failed to persist DPIA records: {e}")))?;
    }
    Ok(())
}

async fn persist_breach_playbooks(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.breach_playbooks_path {
        let records = state.breach_playbooks.read().await;
        write_breach_playbooks_atomic(path, &records)
            .map_err(|e| ApiError::Internal(format!("failed to persist breach playbooks: {e}")))?;
    }
    Ok(())
}

async fn persist_transfer_controls(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.transfer_controls_path {
        let records = state.transfer_controls.read().await;
        write_transfer_controls_atomic(path, &records)
            .map_err(|e| ApiError::Internal(format!("failed to persist transfer controls: {e}")))?;
    }
    Ok(())
}

async fn persist_retention_policies(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.retention_policies_path {
        let records = state.retention_policies.read().await;
        write_retention_policies_atomic(path, &records).map_err(|e| {
            ApiError::Internal(format!("failed to persist retention policies: {e}"))
        })?;
    }
    Ok(())
}

fn persist_retention_execution_records_locked(
    state: &AppState,
    records: &HashMap<String, RetentionExecutionRecord>,
) -> Result<(), ApiError> {
    if let Some(path) = &state.retention_execution_records_path {
        write_retention_execution_records_atomic(path, records).map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist retention execution records: {e}"
            ))
        })?;
    }
    Ok(())
}

fn persist_retention_candidate_resolution_records_locked(
    state: &AppState,
    records: &HashMap<String, RetentionCandidateResolutionRecord>,
) -> Result<(), ApiError> {
    if let Some(path) = &state.retention_candidate_resolutions_path {
        write_retention_candidate_resolution_records_atomic(path, records).map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist retention candidate resolution records: {e}"
            ))
        })?;
    }
    Ok(())
}

/// `GET /v1/privacy/users/{id}/export` — non-secret GDPR/DSR JSON export for one user.
///
/// Requires `user.manage` at Global. A caller without that authority receives the same generic 403
/// as other RBAC gates; a caller that clears the gate receives the ordinary honest 404 for an
/// unknown target, matching the local admin endpoints.
pub async fn export_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<PrivacyExport>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;

    let target = UserId(id);
    let user = {
        let users = state.users.read().await;
        users.get(&target).cloned().ok_or(ApiError::NotFound)?
    };

    let role_assignments = role_assignments(&state, &user).await;
    let ledger_event_refs = ledger_refs(&state, &user).await;

    Ok(Json(PrivacyExport {
        exported_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
        scope: format!("user:{target}"),
        format_version: FORMAT_VERSION,
        redaction_notes: vec![
            "credential verifiers and wrapped private key material are excluded",
            "ledger entries are references only: payload digests and chain hashes, not payload bodies",
        ],
        exclusions: vec![
            "password_hash",
            "recovery_hash",
            "recovery_phrase",
            "api_key_secret",
            "bearer_token",
            "attestation_private_key",
        ],
        user: ExportUser {
            profile: UserView::from(&user),
            role_assignments,
        },
        ledger_event_refs,
    }))
}

/// `POST /v1/privacy/users/{id}/dsr-requests` — create a tracked DSR request for a user.
pub async fn create_dsr_request(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateDsrRequest>,
) -> Result<(StatusCode, Json<DsrRequestView>), ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    let subject_user_id = UserId(id);
    ensure_subject_exists(&state, subject_user_id).await?;

    let request_type = req
        .request_type
        .as_deref()
        .ok_or_else(|| ApiError::Unprocessable("request_type is required".to_owned()))
        .and_then(DsrRequestType::parse)?;
    let actor_name = actor.resolve("api");
    let request = DsrRequest {
        id: DsrRequestId(Uuid::new_v4()),
        subject_user_id,
        request_type,
        status: DsrRequestStatus::Pending,
        reason: clean_optional(req.reason),
        created_at: now_rfc3339(),
        created_by: actor_name.clone(),
        completed_at: None,
        completed_by: None,
        completion_reason: None,
        outcome: None,
        executed_at: None,
        executed_by: None,
        execution_notes: None,
        affected_records: Vec::new(),
        retention_review: None,
        legal_basis_review: None,
        erasure_preflight: None,
        erasure_authorization: None,
        erasure_execution: None,
    };
    let view = DsrRequestView::from(&request);
    state.dsr_requests.write().await.insert(request.id, request);
    persist_dsr_requests(&state).await?;
    record_dsr_event(
        &state,
        &view,
        DSR_CREATED_KIND,
        "DSR request created",
        &actor_name,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/users/{id}/dsr-requests` — list tracked DSR requests for a user.
pub async fn list_dsr_requests_for_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<DsrRequestView>>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    let subject_user_id = UserId(id);
    ensure_subject_exists(&state, subject_user_id).await?;

    let requests = state.dsr_requests.read().await;
    let mut list: Vec<&DsrRequest> = requests
        .values()
        .filter(|req| req.subject_user_id == subject_user_id)
        .collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(list.into_iter().map(DsrRequestView::from).collect()))
}

/// `POST /v1/privacy/dsr-requests/{id}/complete` — mark a tracked DSR request complete.
pub async fn complete_dsr_request(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Option<Json<CompleteDsrRequest>>,
) -> Result<Json<DsrRequestView>, ApiError> {
    let req = body.map(|Json(req)| req).unwrap_or_default();
    complete_dsr_request_inner(
        &state,
        DsrRequestId(id),
        None,
        DsrExecutionInput::from(req),
        &actor,
        &attestor,
    )
    .await
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/complete` — user-scoped complete.
pub async fn complete_user_dsr_request(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    body: Option<Json<CompleteDsrRequest>>,
) -> Result<Json<DsrRequestView>, ApiError> {
    let req = body.map(|Json(req)| req).unwrap_or_default();
    complete_dsr_request_inner(
        &state,
        DsrRequestId(request_id),
        Some(UserId(user_id)),
        DsrExecutionInput::from(req),
        &actor,
        &attestor,
    )
    .await
}

/// `PATCH /v1/privacy/dsr-requests/{id}` — guarded status transition surface.
pub async fn patch_dsr_request(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchDsrRequest>,
) -> Result<Json<DsrRequestView>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    let target_status = req
        .status
        .as_deref()
        .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
        .and_then(DsrRequestStatus::parse)?;
    if target_status != DsrRequestStatus::Completed {
        return Err(ApiError::Unprocessable(
            "invalid DSR status transition; only pending to completed is allowed".to_owned(),
        ));
    }
    complete_dsr_request_inner(
        &state,
        DsrRequestId(id),
        None,
        DsrExecutionInput::from(req),
        &actor,
        &attestor,
    )
    .await
}

/// `POST /v1/privacy/processors` — create a GDPR processor register record.
pub async fn create_processor_record(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateProcessorRecord>,
) -> Result<(StatusCode, Json<ProcessorRecordView>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let actor_name = actor.resolve("api");
    let now = now_rfc3339();
    let record = ProcessorRecord {
        id: ProcessorRecordId(Uuid::new_v4()),
        name: required_string(req.name, "name")?,
        purpose: required_string(req.purpose, "purpose")?,
        legal_basis: required_string(req.legal_basis, "legal_basis")?,
        data_categories: sanitized_strings(req.data_categories, "data_categories", true)?,
        subprocessors: sanitized_strings(req.subprocessors, "subprocessors", false)?,
        risk_level: req
            .risk_level
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("risk_level is required".to_owned()))
            .and_then(PrivacyRiskLevel::parse)?,
        status: req
            .status
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
            .and_then(PrivacyRecordStatus::parse)?,
        created_at: now.clone(),
        created_by: actor_name.clone(),
        updated_at: now,
        updated_by: actor_name.clone(),
    };
    let view = ProcessorRecordView::from(&record);
    state
        .processor_records
        .write()
        .await
        .insert(record.id, record);
    persist_processor_records(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:processor:{}", view.id),
        PROCESSOR_CREATED_KIND,
        "Processor record created",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/processors` — list sanitized processor register records.
pub async fn list_processor_records(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<ProcessorRecordView>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.processor_records.read().await;
    let mut list: Vec<&ProcessorRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(
        list.into_iter().map(ProcessorRecordView::from).collect(),
    ))
}

/// `PATCH /v1/privacy/processors/{id}` — update a processor register record.
pub async fn patch_processor_record(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchProcessorRecord>,
) -> Result<Json<ProcessorRecordView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let record_id = ProcessorRecordId(id);

    let mut records = state.processor_records.write().await;
    let mut record = records.get(&record_id).cloned().ok_or(ApiError::NotFound)?;
    let changed = apply_processor_patch(&mut record, req, &actor_name)?;
    if !changed {
        return Err(ApiError::Unprocessable(
            "at least one processor record field is required".to_owned(),
        ));
    }
    let view = ProcessorRecordView::from(&record);
    records.insert(record.id, record);
    drop(records);
    persist_processor_records(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:processor:{}", view.id),
        PROCESSOR_UPDATED_KIND,
        "Processor record updated",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok(Json(view))
}

/// `POST /v1/privacy/dpias` — create a DPIA register record.
pub async fn create_dpia_record(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateDpiaRecord>,
) -> Result<(StatusCode, Json<DpiaRecordView>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let actor_name = actor.resolve("api");
    let now = now_rfc3339();
    let record = DpiaRecord {
        id: DpiaRecordId(Uuid::new_v4()),
        title: required_string(req.title, "title")?,
        purpose: required_string(req.purpose, "purpose")?,
        legal_basis: required_string(req.legal_basis, "legal_basis")?,
        data_categories: sanitized_strings(req.data_categories, "data_categories", true)?,
        subprocessors: sanitized_strings(req.subprocessors, "subprocessors", false)?,
        risk_level: req
            .risk_level
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("risk_level is required".to_owned()))
            .and_then(PrivacyRiskLevel::parse)?,
        status: req
            .status
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
            .and_then(PrivacyRecordStatus::parse)?,
        evidence_receipts: req
            .evidence_receipt
            .map(|receipt| validate_dpia_evidence_receipt(receipt, &actor_name))
            .transpose()?
            .into_iter()
            .collect(),
        created_at: now.clone(),
        created_by: actor_name.clone(),
        updated_at: now,
        updated_by: actor_name.clone(),
    };
    let view = DpiaRecordView::from(&record);
    state.dpia_records.write().await.insert(record.id, record);
    persist_dpia_records(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:dpia:{}", view.id),
        DPIA_CREATED_KIND,
        "DPIA record created",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/dpias` — list sanitized DPIA register records.
pub async fn list_dpia_records(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<DpiaRecordView>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.dpia_records.read().await;
    let mut list: Vec<&DpiaRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(list.into_iter().map(DpiaRecordView::from).collect()))
}

/// `GET /v1/privacy/dpia-template` — static local/offline DPIA guidance pack.
pub async fn get_dpia_template(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<DpiaTemplateView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    Ok(Json(dpia_template_view()))
}

/// `PATCH /v1/privacy/dpias/{id}` — update a DPIA register record.
pub async fn patch_dpia_record(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchDpiaRecord>,
) -> Result<Json<DpiaRecordView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let record_id = DpiaRecordId(id);

    let mut records = state.dpia_records.write().await;
    let mut record = records.get(&record_id).cloned().ok_or(ApiError::NotFound)?;
    let changed = apply_dpia_patch(&mut record, req, &actor_name)?;
    if !changed {
        return Err(ApiError::Unprocessable(
            "at least one DPIA record field is required".to_owned(),
        ));
    }
    let view = DpiaRecordView::from(&record);
    records.insert(record.id, record);
    drop(records);
    persist_dpia_records(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:dpia:{}", view.id),
        DPIA_UPDATED_KIND,
        "DPIA record updated",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok(Json(view))
}

/// `POST /v1/privacy/breach-playbooks` — create a breach-response playbook register record.
pub async fn create_breach_playbook(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateBreachPlaybook>,
) -> Result<(StatusCode, Json<BreachPlaybookView>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let actor_name = actor.resolve("api");
    let now = now_rfc3339();
    let record = BreachPlaybookRecord {
        id: BreachPlaybookId(Uuid::new_v4()),
        title: required_privacy_control_segment(
            req.title,
            "title",
            MAX_PRIVACY_CONTROL_NAME_CHARS,
        )?,
        scope: required_privacy_control_segment(
            req.scope,
            "scope",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        detection_channels: sanitized_privacy_control_list(
            req.detection_channels,
            "detection_channels",
            true,
        )?,
        containment_steps: sanitized_privacy_control_list(
            req.containment_steps,
            "containment_steps",
            true,
        )?,
        notification_roles: sanitized_privacy_control_list(
            req.notification_roles,
            "notification_roles",
            false,
        )?,
        authority_notification_window: optional_sensitive_checked_text(
            req.authority_notification_window,
            "authority_notification_window",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        subject_notification_guidance: optional_sensitive_checked_text(
            req.subject_notification_guidance,
            "subject_notification_guidance",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        risk_level: req
            .risk_level
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("risk_level is required".to_owned()))
            .and_then(PrivacyRiskLevel::parse)?,
        status: req
            .status
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
            .and_then(PrivacyRecordStatus::parse)?,
        review_notes: optional_sensitive_checked_text(
            req.review_notes,
            "review_notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        evidence_receipts: req
            .evidence_receipt
            .map(|receipt| validate_breach_evidence_receipt(receipt, &actor_name))
            .transpose()?
            .into_iter()
            .collect(),
        created_at: now.clone(),
        created_by: actor_name.clone(),
        updated_at: now,
        updated_by: actor_name.clone(),
    };
    let view = BreachPlaybookView::from(&record);
    state
        .breach_playbooks
        .write()
        .await
        .insert(record.id, record);
    persist_breach_playbooks(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:breach-playbook:{}", view.id),
        BREACH_PLAYBOOK_CREATED_KIND,
        "Breach-response playbook created",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/breach-playbooks` — list breach-response playbook register records.
pub async fn list_breach_playbooks(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<BreachPlaybookView>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.breach_playbooks.read().await;
    let mut list: Vec<&BreachPlaybookRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(
        list.into_iter().map(BreachPlaybookView::from).collect(),
    ))
}

/// `PATCH /v1/privacy/breach-playbooks/{id}` — update a breach-response playbook record.
pub async fn patch_breach_playbook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchBreachPlaybook>,
) -> Result<Json<BreachPlaybookView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let playbook_id = BreachPlaybookId(id);

    let mut records = state.breach_playbooks.write().await;
    let mut record = records
        .get(&playbook_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let changed = apply_breach_playbook_patch(&mut record, req, &actor_name)?;
    if !changed {
        return Err(ApiError::Unprocessable(
            "at least one breach playbook field is required".to_owned(),
        ));
    }
    let view = BreachPlaybookView::from(&record);
    records.insert(record.id, record);
    drop(records);
    persist_breach_playbooks(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:breach-playbook:{}", view.id),
        BREACH_PLAYBOOK_UPDATED_KIND,
        "Breach-response playbook updated",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok(Json(view))
}

/// `POST /v1/privacy/transfer-controls` — create a transfer-control register record.
pub async fn create_transfer_control(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateTransferControl>,
) -> Result<(StatusCode, Json<TransferControlView>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let actor_name = actor.resolve("api");
    let now = now_rfc3339();
    let record = TransferControlRecord {
        id: TransferControlId(Uuid::new_v4()),
        name: required_privacy_control_segment(req.name, "name", MAX_PRIVACY_CONTROL_NAME_CHARS)?,
        purpose: required_sensitive_checked_text(
            req.purpose,
            "purpose",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        legal_basis: required_sensitive_checked_text(
            req.legal_basis,
            "legal_basis",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        data_categories: sanitized_privacy_control_list(
            req.data_categories,
            "data_categories",
            true,
        )?,
        recipient: required_privacy_control_segment(
            req.recipient,
            "recipient",
            MAX_PRIVACY_CONTROL_NAME_CHARS,
        )?,
        destination_country: required_privacy_control_segment(
            req.destination_country,
            "destination_country",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        transfer_mechanism: required_privacy_control_segment(
            req.transfer_mechanism,
            "transfer_mechanism",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        safeguards: sanitized_privacy_control_list(req.safeguards, "safeguards", true)?,
        risk_level: req
            .risk_level
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("risk_level is required".to_owned()))
            .and_then(PrivacyRiskLevel::parse)?,
        status: req
            .status
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
            .and_then(PrivacyRecordStatus::parse)?,
        review_notes: optional_sensitive_checked_text(
            req.review_notes,
            "review_notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        evidence_receipts: req
            .evidence_receipt
            .map(|receipt| validate_transfer_evidence_receipt(receipt, &actor_name))
            .transpose()?
            .into_iter()
            .collect(),
        created_at: now.clone(),
        created_by: actor_name.clone(),
        updated_at: now,
        updated_by: actor_name.clone(),
    };
    let view = TransferControlView::from(&record);
    state
        .transfer_controls
        .write()
        .await
        .insert(record.id, record);
    persist_transfer_controls(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:transfer-control:{}", view.id),
        TRANSFER_CONTROL_CREATED_KIND,
        "Transfer-control record created",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/transfer-controls` — list transfer-control records.
pub async fn list_transfer_controls(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<TransferControlView>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.transfer_controls.read().await;
    let mut list: Vec<&TransferControlRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(
        list.into_iter().map(TransferControlView::from).collect(),
    ))
}

/// `PATCH /v1/privacy/transfer-controls/{id}` — update a transfer-control record.
pub async fn patch_transfer_control(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchTransferControl>,
) -> Result<Json<TransferControlView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let control_id = TransferControlId(id);

    let mut records = state.transfer_controls.write().await;
    let mut record = records
        .get(&control_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    let changed = apply_transfer_control_patch(&mut record, req, &actor_name)?;
    if !changed {
        return Err(ApiError::Unprocessable(
            "at least one transfer control field is required".to_owned(),
        ));
    }
    let view = TransferControlView::from(&record);
    records.insert(record.id, record);
    drop(records);
    persist_transfer_controls(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:transfer-control:{}", view.id),
        TRANSFER_CONTROL_UPDATED_KIND,
        "Transfer-control record updated",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok(Json(view))
}

/// `POST /v1/privacy/retention-policies` — create a retention policy register record.
pub async fn create_retention_policy(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateRetentionPolicy>,
) -> Result<(StatusCode, Json<RetentionPolicyView>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let actor_name = actor.resolve("api");
    let now = now_rfc3339();
    let record = RetentionPolicyRecord {
        id: retention_policy_id(req.id)?,
        name: required_retention_segment(req.name, "name", MAX_RETENTION_NAME_CHARS)?,
        scope: required_retention_segment(req.scope, "scope", MAX_RETENTION_FIELD_CHARS)?,
        category: required_retention_segment(req.category, "category", MAX_RETENTION_FIELD_CHARS)?,
        schedule_id: required_retention_segment(
            req.schedule_id,
            "schedule_id",
            MAX_RETENTION_FIELD_CHARS,
        )?,
        retention_period: required_retention_segment(
            req.retention_period,
            "retention_period",
            MAX_RETENTION_FIELD_CHARS,
        )?,
        legal_basis: required_sensitive_checked_text(
            req.legal_basis,
            "legal_basis",
            MAX_RETENTION_TEXT_CHARS,
        )?,
        disposal_action: req
            .disposal_action
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("disposal_action is required".to_owned()))
            .and_then(RetentionDisposalAction::parse)?,
        status: req
            .status
            .as_deref()
            .ok_or_else(|| ApiError::Unprocessable("status is required".to_owned()))
            .and_then(RetentionPolicyStatus::parse)?,
        active: req
            .active
            .ok_or_else(|| ApiError::Unprocessable("active is required".to_owned()))?,
        notes: optional_sensitive_checked_text(req.notes, "notes", MAX_RETENTION_TEXT_CHARS)?,
        created_at: now.clone(),
        created_by: actor_name.clone(),
        updated_at: now,
        updated_by: actor_name.clone(),
    };
    let view = RetentionPolicyView::from(&record);
    let mut records = state.retention_policies.write().await;
    if records.contains_key(&record.id) {
        return Err(ApiError::Conflict(
            "retention policy id already exists".to_owned(),
        ));
    }
    records.insert(record.id, record);
    drop(records);
    persist_retention_policies(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:retention-policy:{}", view.id),
        RETENTION_POLICY_CREATED_KIND,
        "Retention policy created",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(view)))
}

/// `GET /v1/privacy/retention-policies` — list retention policy register records.
pub async fn list_retention_policies(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<RetentionPolicyView>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.retention_policies.read().await;
    let mut list: Vec<&RetentionPolicyRecord> = records.values().collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    Ok(Json(
        list.into_iter().map(RetentionPolicyView::from).collect(),
    ))
}

/// `GET /v1/privacy/retention-executions` — list recorded retention execution requests.
pub async fn list_retention_execution_records(
    State(state): State<AppState>,
    actor: CurrentActor,
    Query(query): Query<RetentionExecutionListQuery>,
) -> Result<Json<Vec<RetentionExecutionRecord>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let status_filter = parse_retention_execution_status_filter(query.status)?;
    let records = state.retention_execution_records.read().await;
    let mut list: Vec<&RetentionExecutionRecord> = records
        .values()
        .filter(|record| match status_filter {
            Some(status) => record.execution_status == status,
            None => true,
        })
        .collect();
    list.sort_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)));
    Ok(Json(list.into_iter().cloned().collect()))
}

/// `GET /v1/privacy/retention-candidate-resolutions` — list evidence-only due-candidate disposition records.
pub async fn list_retention_candidate_resolution_records(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<RetentionCandidateResolutionRecord>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.retention_candidate_resolutions.read().await;
    let mut list: Vec<&RetentionCandidateResolutionRecord> = records.values().collect();
    list.sort_by(|a, b| a.recorded_at.cmp(&b.recorded_at).then(a.id.cmp(&b.id)));
    Ok(Json(list.into_iter().cloned().collect()))
}

/// `POST /v1/privacy/retention-due-candidates/{candidate_id}/resolution` — record local evidence-only disposition.
pub async fn record_retention_candidate_resolution(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<RetentionCandidateResolutionRecord>), ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let candidate = rederive_active_retention_due_candidate(&state, &candidate_id).await?;
    let req = serde_json::from_value::<RetentionCandidateResolutionRequest>(req)
        .map_err(|e| ApiError::Unprocessable(format!("invalid candidate resolution body: {e}")))?;
    let resolution = validate_retention_candidate_resolution(req, &candidate)?;
    let record = build_retention_candidate_resolution_record(&actor_name, &candidate, resolution);

    {
        let mut records = state.retention_candidate_resolutions.write().await;
        records.insert(record.id.clone(), record.clone());
        persist_retention_candidate_resolution_records_locked(&state, &records)?;
    }

    record_privacy_event(
        &state,
        &format!("privacy:retention-candidate-resolution:{}", record.id),
        RETENTION_CANDIDATE_RESOLUTION_RECORDED_KIND,
        "Retention due-candidate evidence-only disposition recorded",
        &actor_name,
        &record,
        &attestor,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(record)))
}

/// `POST /v1/privacy/retention-executions/{id}/review-closure` — close operator review evidence without executing disposal.
pub async fn close_retention_execution_review(
    State(state): State<AppState>,
    Path(id): Path<String>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<RetentionExecutionRecord>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let req = serde_json::from_value::<RetentionReviewClosureRequest>(req)
        .map_err(|e| ApiError::Unprocessable(format!("invalid review closure body: {e}")))?;
    let closure = validate_retention_review_closure(req)?;
    let mut should_record_ledger = false;
    let record = {
        let mut records = state.retention_execution_records.write().await;
        let mut record = records.get(&id).cloned().ok_or(ApiError::NotFound)?;
        validate_retention_review_closure_decision_for_record(&record, closure.decision)?;

        if record.decision_state == RetentionExecutionDecisionState::ReviewClosed {
            if retention_review_closure_matches(&record, &closure) {
                record
            } else {
                return Err(ApiError::Conflict(
                    "retention execution review closure already exists with different evidence"
                        .to_owned(),
                ));
            }
        } else {
            apply_retention_review_closure(&mut record, closure, &actor_name);
            records.insert(record.id.clone(), record.clone());
            persist_retention_execution_records_locked(&state, &records)?;
            should_record_ledger = true;
            record
        }
    };

    if should_record_ledger {
        let scope = format!("privacy:retention-execution:{}", record.id);
        let event = retention_review_closure_ledger_event(&record);
        record_privacy_event(
            &state,
            &scope,
            RETENTION_EXECUTION_REVIEW_CLOSED_KIND,
            "Retention execution review closure recorded as bounded evidence acknowledgment",
            &actor_name,
            &event,
            &attestor,
        )
        .await?;
    }

    Ok(Json(record))
}

/// `GET /v1/privacy/retention-due-candidates` — read-only closed-book archive retention scanner.
pub async fn list_retention_due_candidates(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<RetentionDueCandidatesReport>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let today = OffsetDateTime::now_utc().date();
    let policies = state.retention_policies.read().await;
    let candidate_policies = archive_retention_candidate_policies(&policies);
    let books = state.books.read().await;
    let prior_execution_records = state.retention_execution_records.read().await;
    let candidate_resolution_records = state.retention_candidate_resolutions.read().await;
    let mut candidates = Vec::new();
    let mut suppressed_by_bounded_evidence_count = 0usize;
    let mut candidate_resolution_record_count = 0usize;
    let mut candidates_with_resolution_count = 0usize;

    for book in books
        .values()
        .filter(|book| book.state == BookState::Closed && book.termo_encerramento.is_some())
    {
        let Some(termo) = book.termo_encerramento.as_ref() else {
            continue;
        };
        for policy in &candidate_policies {
            if let Some(mut candidate) = retention_due_candidate_for_book_policy(
                book,
                termo.closing_date,
                policy,
                &policies,
                &prior_execution_records,
                today,
            ) {
                if retention_due_candidate_has_bounded_evidence_suppression(&candidate) {
                    suppressed_by_bounded_evidence_count += 1;
                } else {
                    let matching_resolution_count = apply_candidate_resolution_projection(
                        &mut candidate,
                        &candidate_resolution_records,
                    );
                    candidate_resolution_record_count += matching_resolution_count;
                    if matching_resolution_count > 0 {
                        candidates_with_resolution_count += 1;
                    }
                    candidates.push(candidate);
                }
            }
        }
    }

    candidates.sort_by(|a, b| {
        a.due_date
            .cmp(&b.due_date)
            .then(a.record_id.cmp(&b.record_id))
            .then(a.policy_id.cmp(&b.policy_id))
    });
    let candidate_count = candidates.len();
    let suppressed_candidate_count = suppressed_by_bounded_evidence_count;
    let suppression_summary = (suppressed_by_bounded_evidence_count > 0).then_some(
        RetentionDueCandidatesSuppressionSummary {
            suppressed_by_bounded_evidence_count,
            note: RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE,
        },
    );
    Ok(Json(RetentionDueCandidatesReport {
        generated_at: now_rfc3339(),
        scope: ARCHIVE_RETENTION_POLICY_SCOPE,
        category: ARCHIVE_RETENTION_POLICY_CATEGORY,
        candidate_count,
        suppressed_candidate_count,
        suppressed_by_bounded_evidence_count,
        candidate_resolution_record_count,
        candidates_with_resolution_count,
        suppression_summary,
        candidates,
    }))
}

/// `PATCH /v1/privacy/retention-policies/{id}` — update a retention policy register record.
pub async fn patch_retention_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<PatchRetentionPolicy>,
) -> Result<Json<RetentionPolicyView>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let actor_name = actor.resolve("api");
    let policy_id = RetentionPolicyId(id);

    let mut records = state.retention_policies.write().await;
    let mut record = records.get(&policy_id).cloned().ok_or(ApiError::NotFound)?;
    let changed = apply_retention_policy_patch(&mut record, req, &actor_name)?;
    if !changed {
        return Err(ApiError::Unprocessable(
            "at least one retention policy field is required".to_owned(),
        ));
    }
    let view = RetentionPolicyView::from(&record);
    records.insert(record.id, record);
    drop(records);
    persist_retention_policies(&state).await?;
    record_privacy_event(
        &state,
        &format!("privacy:retention-policy:{}", view.id),
        RETENTION_POLICY_UPDATED_KIND,
        "Retention policy updated",
        &actor_name,
        &view,
        &attestor,
    )
    .await?;

    Ok(Json(view))
}

/// `POST /v1/privacy/retention-policies/dry-run` — match policies without executing disposal.
pub async fn retention_policy_dry_run(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RetentionDryRunRequest>,
) -> Result<Json<RetentionDryRunReport>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;

    let scope = required_retention_segment(req.scope, "scope", MAX_RETENTION_FIELD_CHARS)?;
    let category = required_retention_segment(req.category, "category", MAX_RETENTION_FIELD_CHARS)?;
    let record_id = retention_record_reference(req.record_id)?;
    let execution_request = validate_retention_execution_request(req.execution_request)?;
    let actor_name = actor.resolve("api");
    let candidate = RetentionDryRunCandidate {
        scope,
        category,
        record_id,
    };

    let records = state.retention_policies.read().await;
    let mut list: Vec<&RetentionPolicyRecord> = records
        .values()
        .filter(|record| retention_policy_applies(record, &candidate.scope, &candidate.category))
        .collect();
    list.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    let mut matches: Vec<RetentionDryRunMatch> = list
        .into_iter()
        .map(|record| RetentionDryRunMatch {
            policy_id: record.id.to_string(),
            name: record.name.clone(),
            scope: record.scope.clone(),
            category: record.category.clone(),
            schedule_id: record.schedule_id.clone(),
            retention_period: record.retention_period.clone(),
            disposal_action: record.disposal_action,
            status: record.status,
            active: record.active,
            destructive_action: record.disposal_action.is_destructive(),
            would_execute: false,
            reason: "scope/category matched an active policy; dry-run only",
        })
        .collect();
    let matched_count = matches.len();
    let mut new_execution_record = None;
    let execution_record = match execution_request {
        Some(execution_request) => {
            let mut prior_execution_records = state.retention_execution_records.write().await;
            if let Some(existing_record) = retention_existing_awaiting_review_execution(
                &candidate,
                &execution_request,
                &prior_execution_records,
            ) {
                Some(existing_record)
            } else {
                let record = build_retention_execution_record(
                    &actor_name,
                    &candidate,
                    &records,
                    &matches,
                    &prior_execution_records,
                    execution_request,
                );
                prior_execution_records.insert(record.id.clone(), record.clone());
                persist_retention_execution_records_locked(&state, &prior_execution_records)?;
                new_execution_record = Some(record.clone());
                Some(record)
            }
        }
        None => None,
    };
    drop(records);
    if let Some(record) = &execution_record {
        apply_execution_result_to_matches(record, &mut matches);
    }

    if let Some(record) = &new_execution_record {
        let scope = format!("privacy:retention-execution:{}", record.id);
        record_privacy_event(
            &state,
            &scope,
            RETENTION_EXECUTION_REQUESTED_KIND,
            "Retention execution request recorded without destructive execution",
            &actor_name,
            record,
            &attestor,
        )
        .await?;
    }
    let mode = if execution_record.is_some() {
        "execution_request"
    } else {
        "dry_run"
    };

    Ok(Json(RetentionDryRunReport {
        mode,
        execution_supported: true,
        destructive_execution_supported: false,
        candidate,
        matched_count,
        matches,
        execution_record,
    }))
}

fn archive_retention_candidate_policies(
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
) -> Vec<&RetentionPolicyRecord> {
    let mut policies: Vec<&RetentionPolicyRecord> = records
        .values()
        .filter(|record| {
            retention_policy_applies(
                record,
                ARCHIVE_RETENTION_POLICY_SCOPE,
                ARCHIVE_RETENTION_POLICY_CATEGORY,
            ) && record.disposal_action != RetentionDisposalAction::LegalHold
        })
        .collect();
    policies.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    policies
}

fn retention_due_candidate_for_book_policy(
    book: &Book,
    closing_date: Date,
    policy: &RetentionPolicyRecord,
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
    prior_execution_records: &HashMap<String, RetentionExecutionRecord>,
    today: Date,
) -> Option<RetentionDueCandidate> {
    let mut findings = Vec::new();
    let due_date = match retention_due_date(closing_date, &policy.retention_period) {
        Ok(due_date) => {
            if due_date > today {
                return None;
            }
            Some(due_date)
        }
        Err(message) => {
            findings.push(RetentionDueFinding {
                code: "unsupported_retention_period".to_owned(),
                message,
                policy_id: Some(policy.id.to_string()),
            });
            None
        }
    };
    let record_id = book.id.to_string();
    let candidate = RetentionDryRunCandidate {
        scope: ARCHIVE_RETENTION_POLICY_SCOPE.to_owned(),
        category: ARCHIVE_RETENTION_POLICY_CATEGORY.to_owned(),
        record_id: Some(record_id.clone()),
    };
    let matches = vec![RetentionDryRunMatch {
        policy_id: policy.id.to_string(),
        name: policy.name.clone(),
        scope: policy.scope.clone(),
        category: policy.category.clone(),
        schedule_id: policy.schedule_id.clone(),
        retention_period: policy.retention_period.clone(),
        disposal_action: policy.disposal_action,
        status: policy.status,
        active: policy.active,
        destructive_action: policy.disposal_action.is_destructive(),
        would_execute: false,
        reason: "scope/category matched an active archive retention policy; candidate scan only",
    }];
    let review_request = ValidatedRetentionExecutionRequest {
        requested_policy_id: Some(policy.id),
        execution_intent: RetentionExecutionIntent::ReviewOnly,
        operator_notes: None,
        evidence: Vec::new(),
        approval: None,
    };
    let execution_record = retention_existing_awaiting_review_execution(
        &candidate,
        &review_request,
        prior_execution_records,
    )
    .unwrap_or_else(|| {
        build_retention_execution_record(
            "retention-due-candidate-scanner",
            &candidate,
            records,
            &matches,
            prior_execution_records,
            review_request,
        )
    });
    let prior_execution = retention_prior_bounded_due_candidate_projection(
        &candidate,
        policy,
        prior_execution_records,
    );
    let book_hold_blocker = book
        .legal_hold
        .as_ref()
        .map(retention_due_book_legal_hold_blocker);
    let mut legal_hold_blockers = execution_record
        .legal_hold_blockers
        .iter()
        .map(|blocker| RetentionDueLegalHoldBlocker {
            source: "retention_policy",
            policy_id: Some(blocker.policy_id.clone()),
            name: Some(blocker.name.clone()),
            schedule_id: Some(blocker.schedule_id.clone()),
            retention_period: Some(blocker.retention_period.clone()),
            reason: blocker.reason.clone(),
        })
        .collect::<Vec<_>>();
    if let Some(blocker) = book_hold_blocker {
        legal_hold_blockers.push(blocker);
    }

    let mut blockers = execution_record.workflow.blockers.clone();
    let mut required_approvals = execution_record.workflow.required_approvals.clone();
    if book.legal_hold.is_some()
        && !required_approvals
            .iter()
            .any(|approval| approval.code == "legal_hold_owner_release")
    {
        required_approvals.push(retention_required_approval(
            "legal_hold_owner_release",
            "legal_hold_owner",
            "resolve the persisted book legal hold before disposal review can continue",
        ));
    }
    if book.legal_hold.is_some()
        && !blockers
            .iter()
            .any(|blocker| blocker.code == "legal_hold_release")
    {
        blockers.push(retention_blocker(
            "legal_hold_release",
            "active persisted book legal hold blocks retention disposal review",
            None,
        ));
    }
    if !findings.is_empty() {
        blockers.push(retention_blocker(
            "unsupported_retention_period",
            "retention period syntax is unsupported; candidate requires policy register review",
            Some(policy.id.to_string()),
        ));
        if !required_approvals
            .iter()
            .any(|approval| approval.code == "policy_register_review")
        {
            required_approvals.push(retention_required_approval(
                "policy_register_review",
                "privacy_or_settings_manager",
                "replace unsupported retention period syntax with the supported single-component period format",
            ));
        }
    }

    let (outcome, status, next_step) = if findings
        .iter()
        .any(|finding| finding.code == "unsupported_retention_period")
    {
        (
            "unsupported_retention_period".to_owned(),
            "blocked".to_owned(),
            "Review the retention policy period syntax; no disposal has been executed.".to_owned(),
        )
    } else if book.legal_hold.is_some()
        && execution_record.outcome != RetentionExecutionOutcome::BlockedLegalHold
    {
        (
            "blocked_legal_hold".to_owned(),
            "blocked".to_owned(),
            "Resolve the legal hold approval before continuing; no disposal has been executed."
                .to_owned(),
        )
    } else {
        (
            retention_execution_outcome_wire(execution_record.outcome).to_owned(),
            retention_execution_status_wire(execution_record.execution_status).to_owned(),
            execution_record.workflow.next_step.clone(),
        )
    };
    let (candidate_evidence_state, evidence_next_step) =
        retention_due_candidate_evidence_progression(
            &status,
            prior_execution.as_ref(),
            &next_step,
            execution_record.outcome,
        );

    let mut candidate = RetentionDueCandidate {
        candidate_id: format!(
            "{}:{}:{}:{}",
            ARCHIVE_RETENTION_POLICY_SCOPE, ARCHIVE_RETENTION_POLICY_CATEGORY, book.id, policy.id
        ),
        candidate_fingerprint: String::new(),
        scope: ARCHIVE_RETENTION_POLICY_SCOPE.to_owned(),
        category: ARCHIVE_RETENTION_POLICY_CATEGORY.to_owned(),
        record_id,
        book_id: book.id.to_string(),
        entity_id: book.entity_id.to_string(),
        closing_date: format_date(closing_date),
        due_date: due_date.map(format_date),
        overdue: due_date.is_some_and(|due_date| due_date < today),
        policy_id: policy.id.to_string(),
        policy_name: policy.name.clone(),
        schedule_id: policy.schedule_id.clone(),
        retention_period: policy.retention_period.clone(),
        disposal_action: policy.disposal_action,
        destructive_action: policy.disposal_action.is_destructive(),
        legal_hold_blockers,
        required_approvals,
        blockers,
        findings,
        outcome,
        status,
        candidate_evidence_state,
        evidence_next_step,
        would_execute: false,
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        prior_execution,
        candidate_resolution_record_count: 0,
        latest_resolution: None,
        next_step,
    };
    candidate.candidate_fingerprint = retention_due_candidate_fingerprint(&candidate);
    Some(candidate)
}

fn apply_candidate_resolution_projection(
    candidate: &mut RetentionDueCandidate,
    records: &HashMap<String, RetentionCandidateResolutionRecord>,
) -> usize {
    let mut matches: Vec<&RetentionCandidateResolutionRecord> = records
        .values()
        .filter(|record| {
            record.candidate_id == candidate.candidate_id
                && record.candidate_fingerprint == candidate.candidate_fingerprint
        })
        .collect();
    matches.sort_by(|a, b| a.recorded_at.cmp(&b.recorded_at).then(a.id.cmp(&b.id)));
    let count = matches.len();
    candidate.candidate_resolution_record_count = count;
    candidate.latest_resolution = matches
        .last()
        .map(|record| retention_candidate_resolution_summary(record));
    count
}

fn retention_candidate_resolution_summary(
    record: &RetentionCandidateResolutionRecord,
) -> RetentionCandidateResolutionSummary {
    RetentionCandidateResolutionSummary {
        id: record.id.clone(),
        candidate_fingerprint: record.candidate_fingerprint.clone(),
        recorded_at: record.recorded_at.clone(),
        recorded_by: record.recorded_by.clone(),
        disposition: record.disposition,
        evidence_count: record.evidence_count,
        note: record.note.clone(),
        evidence_only: true,
        destructive_disposal_completed: false,
        disposal_completed: false,
        full_erasure_completed: false,
        erasure_completed: false,
        legal_hold_mutated: false,
        legal_hold_resolved: false,
        retention_policy_mutated: false,
        retention_policy_changed: false,
        legal_completion_claimed: false,
        legal_disposal_completed: false,
        next_step: record.next_step.clone(),
    }
}

fn retention_due_candidate_fingerprint(candidate: &RetentionDueCandidate) -> String {
    let payload = serde_json::json!({
        "candidate_id": &candidate.candidate_id,
        "scope": &candidate.scope,
        "category": &candidate.category,
        "record_id": &candidate.record_id,
        "book_id": &candidate.book_id,
        "entity_id": &candidate.entity_id,
        "closing_date": &candidate.closing_date,
        "due_date": &candidate.due_date,
        "overdue": candidate.overdue,
        "policy_id": &candidate.policy_id,
        "policy_name": &candidate.policy_name,
        "schedule_id": &candidate.schedule_id,
        "retention_period": &candidate.retention_period,
        "disposal_action": candidate.disposal_action,
        "destructive_action": candidate.destructive_action,
        "legal_hold_blockers": &candidate.legal_hold_blockers,
        "required_approvals": &candidate.required_approvals,
        "blockers": &candidate.blockers,
        "findings": &candidate.findings,
        "outcome": &candidate.outcome,
        "status": &candidate.status,
        "candidate_evidence_state": candidate.candidate_evidence_state,
        "prior_execution": &candidate.prior_execution,
        "next_step": &candidate.next_step,
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    crate::hex::hex(&digest)
}

fn retention_candidate_resolution_snapshot(
    candidate: &RetentionDueCandidate,
) -> RetentionCandidateResolutionSnapshot {
    RetentionCandidateResolutionSnapshot {
        candidate_id: candidate.candidate_id.clone(),
        candidate_fingerprint: candidate.candidate_fingerprint.clone(),
        scope: candidate.scope.clone(),
        category: candidate.category.clone(),
        record_id: candidate.record_id.clone(),
        book_id: candidate.book_id.clone(),
        entity_id: candidate.entity_id.clone(),
        closing_date: candidate.closing_date.clone(),
        due_date: candidate.due_date.clone(),
        overdue: candidate.overdue,
        policy_id: candidate.policy_id.clone(),
        policy_name: candidate.policy_name.clone(),
        schedule_id: candidate.schedule_id.clone(),
        retention_period: candidate.retention_period.clone(),
        disposal_action: candidate.disposal_action,
        destructive_action: candidate.destructive_action,
        outcome: candidate.outcome.clone(),
        status: candidate.status.clone(),
        candidate_evidence_state: candidate.candidate_evidence_state,
        legal_hold_blocker_count: candidate.legal_hold_blockers.len(),
        required_approval_count: candidate.required_approvals.len(),
        blocker_count: candidate.blockers.len(),
        finding_count: candidate.findings.len(),
    }
}

async fn rederive_active_retention_due_candidate(
    state: &AppState,
    candidate_id: &str,
) -> Result<RetentionDueCandidate, ApiError> {
    let today = OffsetDateTime::now_utc().date();
    let policies = state.retention_policies.read().await;
    let candidate_policies = archive_retention_candidate_policies(&policies);
    let books = state.books.read().await;
    let prior_execution_records = state.retention_execution_records.read().await;

    for book in books
        .values()
        .filter(|book| book.state == BookState::Closed && book.termo_encerramento.is_some())
    {
        let Some(termo) = book.termo_encerramento.as_ref() else {
            continue;
        };
        for policy in &candidate_policies {
            let Some(candidate) = retention_due_candidate_for_book_policy(
                book,
                termo.closing_date,
                policy,
                &policies,
                &prior_execution_records,
                today,
            ) else {
                continue;
            };
            if candidate.candidate_id != candidate_id {
                continue;
            }
            if retention_due_candidate_has_bounded_evidence_suppression(&candidate) {
                return Err(ApiError::Unprocessable(
                    "candidate is no longer an active due candidate because prior bounded evidence is available"
                        .to_owned(),
                ));
            }
            return Ok(candidate);
        }
    }

    Err(ApiError::NotFound)
}

fn build_retention_candidate_resolution_record(
    actor_name: &str,
    candidate: &RetentionDueCandidate,
    resolution: ValidatedRetentionCandidateResolution,
) -> RetentionCandidateResolutionRecord {
    let evidence_count = resolution.evidence.len();
    RetentionCandidateResolutionRecord {
        id: Uuid::new_v4().to_string(),
        candidate_id: candidate.candidate_id.clone(),
        candidate_fingerprint: candidate.candidate_fingerprint.clone(),
        recorded_at: now_rfc3339(),
        recorded_by: actor_name.to_owned(),
        disposition: resolution.disposition,
        note: resolution.note,
        evidence: resolution.evidence,
        evidence_count,
        candidate: retention_candidate_resolution_snapshot(candidate),
        evidence_only: true,
        destructive_disposal_completed: false,
        disposal_completed: false,
        full_erasure_completed: false,
        erasure_completed: false,
        legal_hold_mutated: false,
        legal_hold_resolved: false,
        retention_policy_mutated: false,
        retention_policy_changed: false,
        legal_completion_claimed: false,
        legal_disposal_completed: false,
        next_step: retention_candidate_resolution_next_step(candidate, resolution.disposition)
            .to_owned(),
    }
}

fn retention_candidate_resolution_next_step(
    candidate: &RetentionDueCandidate,
    disposition: RetentionCandidateDisposition,
) -> &'static str {
    match disposition {
        RetentionCandidateDisposition::EvidenceAcknowledged => {
            "Evidence-only disposition recorded; the due candidate remains available for separate governance review."
        }
        RetentionCandidateDisposition::FollowUpRequired => {
            "Follow-up evidence recorded; the due candidate remains available for separate governance review."
        }
        RetentionCandidateDisposition::BlockedFollowUp => {
            if retention_candidate_requires_follow_up_resolution(candidate) {
                "Blocked follow-up evidence recorded; blockers remain active for separate governance review."
            } else {
                "Follow-up evidence recorded; the due candidate remains available for separate governance review."
            }
        }
    }
}

fn retention_due_candidate_has_bounded_evidence_suppression(
    candidate: &RetentionDueCandidate,
) -> bool {
    let Some(prior_execution) = candidate.prior_execution.as_ref() else {
        return false;
    };

    matches!(
        (candidate.disposal_action, prior_execution.outcome.as_str()),
        (RetentionDisposalAction::Archive, "bounded_archive_recorded")
            | (
                RetentionDisposalAction::NoAction,
                "bounded_no_action_recorded"
            )
    ) && prior_execution.execution_status
        == retention_execution_status_wire(RetentionExecutionStatus::Executed)
        && prior_execution.bounded_executor
        && prior_execution.targets_acted_count > 0
        && !prior_execution.destructive_disposal_completed
        && !prior_execution.full_erasure_completed
        && candidate.due_date.is_some()
        && !candidate.destructive_action
        && candidate.legal_hold_blockers.is_empty()
        && candidate.blockers.is_empty()
        && candidate.findings.is_empty()
}

fn retention_due_book_legal_hold_blocker(hold: &LegalHold) -> RetentionDueLegalHoldBlocker {
    let set_at = hold.set_at.format(&Rfc3339).unwrap_or_default();
    RetentionDueLegalHoldBlocker {
        source: "book",
        policy_id: None,
        name: None,
        schedule_id: None,
        retention_period: None,
        reason: format!(
            "persisted book legal hold set by {} at {}: {}",
            hold.actor, set_at, hold.reason
        ),
    }
}

fn retention_due_date(closing_date: Date, raw_period: &str) -> Result<Date, String> {
    match parse_safe_retention_period(raw_period)? {
        SafeRetentionPeriod::Years(years) => add_months(closing_date, years.saturating_mul(12)),
        SafeRetentionPeriod::Months(months) => add_months(closing_date, months),
        SafeRetentionPeriod::Days(days) => closing_date
            .checked_add(Duration::days(days))
            .ok_or_else(|| "retention_period would overflow a valid date".to_owned()),
    }
}

enum SafeRetentionPeriod {
    Years(i32),
    Months(i32),
    Days(i64),
}

fn parse_safe_retention_period(raw_period: &str) -> Result<SafeRetentionPeriod, String> {
    let period = raw_period.trim();
    if period.len() < 3 || !period.starts_with('P') || period.contains('T') {
        return Err(format!(
            "unsupported_retention_period: {period:?}; expected a single-component period like P10Y, P6M, or P30D"
        ));
    }
    let mut component = period
        .strip_prefix('P')
        .expect("starts_with checked above")
        .chars();
    let Some(unit) = component.next_back() else {
        return Err(format!(
            "unsupported_retention_period: {period:?}; expected PnY, PnM, or PnD"
        ));
    };
    let number = component.as_str();
    if number.is_empty() || !number.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!(
            "unsupported_retention_period: {period:?}; expected a positive integer component"
        ));
    }
    let value: i64 = number.parse().map_err(|_| {
        format!("unsupported_retention_period: {period:?}; integer component is too large")
    })?;
    if value < 0 {
        return Err(format!(
            "unsupported_retention_period: {period:?}; negative periods are not supported"
        ));
    }
    match unit {
        'Y' => i32::try_from(value)
            .map(SafeRetentionPeriod::Years)
            .map_err(|_| {
                format!("unsupported_retention_period: {period:?}; year component is too large")
            }),
        'M' => i32::try_from(value)
            .map(SafeRetentionPeriod::Months)
            .map_err(|_| {
                format!("unsupported_retention_period: {period:?}; month component is too large")
            }),
        'D' => Ok(SafeRetentionPeriod::Days(value)),
        _ => Err(format!(
            "unsupported_retention_period: {period:?}; expected PnY, PnM, or PnD"
        )),
    }
}

fn add_months(date: Date, months: i32) -> Result<Date, String> {
    let month_number = i32::from(month_number(date.month()));
    let total = date
        .year()
        .checked_mul(12)
        .and_then(|year_months| year_months.checked_add(month_number - 1))
        .and_then(|base| base.checked_add(months))
        .ok_or_else(|| "retention_period would overflow a valid date".to_owned())?;
    let year = total.div_euclid(12);
    let month = month_from_number((total.rem_euclid(12) + 1) as u8)?;
    let day = date.day().min(days_in_month(year, month));
    Date::from_calendar_date(year, month, day)
        .map_err(|_| "retention_period would overflow a valid date".to_owned())
}

fn month_number(month: Month) -> u8 {
    match month {
        Month::January => 1,
        Month::February => 2,
        Month::March => 3,
        Month::April => 4,
        Month::May => 5,
        Month::June => 6,
        Month::July => 7,
        Month::August => 8,
        Month::September => 9,
        Month::October => 10,
        Month::November => 11,
        Month::December => 12,
    }
}

fn month_from_number(month: u8) -> Result<Month, String> {
    match month {
        1 => Ok(Month::January),
        2 => Ok(Month::February),
        3 => Ok(Month::March),
        4 => Ok(Month::April),
        5 => Ok(Month::May),
        6 => Ok(Month::June),
        7 => Ok(Month::July),
        8 => Ok(Month::August),
        9 => Ok(Month::September),
        10 => Ok(Month::October),
        11 => Ok(Month::November),
        12 => Ok(Month::December),
        _ => Err("retention_period would produce an invalid month".to_owned()),
    }
}

fn days_in_month(year: i32, month: Month) -> u8 {
    match month {
        Month::January
        | Month::March
        | Month::May
        | Month::July
        | Month::August
        | Month::October
        | Month::December => 31,
        Month::April | Month::June | Month::September | Month::November => 30,
        Month::February if is_leap_year(year) => 29,
        Month::February => 28,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn retention_execution_outcome_wire(outcome: RetentionExecutionOutcome) -> &'static str {
    match outcome {
        RetentionExecutionOutcome::BlockedMissingPolicy => "blocked_missing_policy",
        RetentionExecutionOutcome::BlockedStalePolicy => "blocked_stale_policy",
        RetentionExecutionOutcome::BlockedPolicyMismatch => "blocked_policy_mismatch",
        RetentionExecutionOutcome::BlockedLegalHold => "blocked_legal_hold",
        RetentionExecutionOutcome::BlockedDestructiveAction => "blocked_destructive_action",
        RetentionExecutionOutcome::BlockedApprovalMismatch => "blocked_approval_mismatch",
        RetentionExecutionOutcome::BlockedMissingTarget => "blocked_missing_target",
        RetentionExecutionOutcome::ManualReviewRequired => "manual_review_required",
        RetentionExecutionOutcome::BoundedArchiveRecorded => "bounded_archive_recorded",
        RetentionExecutionOutcome::BoundedNoActionRecorded => "bounded_no_action_recorded",
        RetentionExecutionOutcome::AlreadyExecuted => "already_executed",
    }
}

fn retention_execution_status_wire(status: RetentionExecutionStatus) -> &'static str {
    match status {
        RetentionExecutionStatus::AwaitingReview => "awaiting_review",
        RetentionExecutionStatus::Blocked => "blocked",
        RetentionExecutionStatus::Executed => "executed",
    }
}

fn retention_review_closure_decision_wire(
    decision: RetentionReviewClosureDecision,
) -> &'static str {
    match decision {
        RetentionReviewClosureDecision::ReviewEvidenceAcknowledged => {
            "review_evidence_acknowledged"
        }
        RetentionReviewClosureDecision::BoundedEvidenceAcknowledged => {
            "bounded_evidence_acknowledged"
        }
        RetentionReviewClosureDecision::BlockedEvidenceAcknowledged => {
            "blocked_evidence_acknowledged"
        }
    }
}

async fn complete_dsr_request_inner(
    state: &AppState,
    request_id: DsrRequestId,
    expected_subject: Option<UserId>,
    execution: DsrExecutionInput,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<Json<DsrRequestView>, ApiError> {
    require_permission(state, actor, Permission::UserManage, Scope::Global).await?;
    let actor_name = actor.resolve("api");
    let executed_at = now_rfc3339();
    let request_snapshot = {
        let requests = state.dsr_requests.read().await;
        let request = requests
            .get(&request_id)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        if expected_subject.is_some_and(|subject| subject != request.subject_user_id) {
            return Err(ApiError::NotFound);
        }
        if request.status != DsrRequestStatus::Pending {
            return Err(ApiError::Conflict(
                "DSR request is not pending; it cannot be completed again".to_owned(),
            ));
        }
        request
    };
    let execution = validate_dsr_execution(execution, request_snapshot.request_type)?;
    let erasure_preflight = if request_snapshot.request_type == DsrRequestType::Erasure {
        Some(
            build_dsr_erasure_preflight(
                state,
                &request_snapshot,
                &actor_name,
                &executed_at,
                execution.erasure_plan.clone().unwrap_or_default(),
            )
            .await,
        )
    } else {
        None
    };

    let mut requests = state.dsr_requests.write().await;
    let mut request = requests
        .get(&request_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if expected_subject.is_some_and(|subject| subject != request.subject_user_id) {
        return Err(ApiError::NotFound);
    }
    if request.status != DsrRequestStatus::Pending {
        return Err(ApiError::Conflict(
            "DSR request is not pending; it cannot be completed again".to_owned(),
        ));
    }

    request.status = DsrRequestStatus::Completed;
    request.completed_at = Some(executed_at.clone());
    request.completed_by = Some(actor_name.clone());
    request.completion_reason = execution.completion_reason;
    request.outcome = Some(execution.outcome);
    request.executed_at = Some(executed_at);
    request.executed_by = Some(actor_name.clone());
    request.execution_notes = execution.execution_notes;
    request.affected_records = execution.affected_records;
    request.retention_review = execution.retention_review;
    request.legal_basis_review = execution.legal_basis_review;
    request.erasure_preflight = erasure_preflight;
    let view = DsrRequestView::from(&request);
    requests.insert(request.id, request);
    drop(requests);
    persist_dsr_requests(state).await?;
    record_dsr_event(
        state,
        &view,
        DSR_COMPLETED_KIND,
        "DSR request completed",
        &actor_name,
        attestor,
    )
    .await?;

    Ok(Json(view))
}

async fn require_privacy_record_manage(
    state: &AppState,
    actor: &CurrentActor,
) -> Result<(), ApiError> {
    let authz = authorizer(state, actor).await?;
    if authz.permits(Permission::UserManage, Scope::Global)
        || authz.permits(Permission::SettingsManage, Scope::Global)
    {
        Ok(())
    } else {
        Err(forbidden())
    }
}

fn apply_processor_patch(
    record: &mut ProcessorRecord,
    req: PatchProcessorRecord,
    actor_name: &str,
) -> Result<bool, ApiError> {
    let mut changed = false;
    if let Some(name) = req.name {
        record.name = clean_required(&name, "name")?;
        changed = true;
    }
    if let Some(purpose) = req.purpose {
        record.purpose = clean_required(&purpose, "purpose")?;
        changed = true;
    }
    if let Some(legal_basis) = req.legal_basis {
        record.legal_basis = clean_required(&legal_basis, "legal_basis")?;
        changed = true;
    }
    if let Some(data_categories) = req.data_categories {
        record.data_categories = sanitized_strings(data_categories, "data_categories", true)?;
        changed = true;
    }
    if let Some(subprocessors) = req.subprocessors {
        record.subprocessors = sanitized_strings(subprocessors, "subprocessors", false)?;
        changed = true;
    }
    if let Some(risk_level) = req.risk_level {
        record.risk_level = PrivacyRiskLevel::parse(&risk_level)?;
        changed = true;
    }
    if let Some(status) = req.status {
        record.status = PrivacyRecordStatus::parse(&status)?;
        changed = true;
    }
    if changed {
        record.updated_at = now_rfc3339();
        record.updated_by = actor_name.to_owned();
    }
    Ok(changed)
}

fn apply_dpia_patch(
    record: &mut DpiaRecord,
    req: PatchDpiaRecord,
    actor_name: &str,
) -> Result<bool, ApiError> {
    let mut changed = false;
    if let Some(title) = req.title {
        record.title = clean_required(&title, "title")?;
        changed = true;
    }
    if let Some(purpose) = req.purpose {
        record.purpose = clean_required(&purpose, "purpose")?;
        changed = true;
    }
    if let Some(legal_basis) = req.legal_basis {
        record.legal_basis = clean_required(&legal_basis, "legal_basis")?;
        changed = true;
    }
    if let Some(data_categories) = req.data_categories {
        record.data_categories = sanitized_strings(data_categories, "data_categories", true)?;
        changed = true;
    }
    if let Some(subprocessors) = req.subprocessors {
        record.subprocessors = sanitized_strings(subprocessors, "subprocessors", false)?;
        changed = true;
    }
    if let Some(risk_level) = req.risk_level {
        record.risk_level = PrivacyRiskLevel::parse(&risk_level)?;
        changed = true;
    }
    if let Some(status) = req.status {
        record.status = PrivacyRecordStatus::parse(&status)?;
        changed = true;
    }
    if let Some(evidence_receipt) = req.evidence_receipt {
        if record.evidence_receipts.len() >= MAX_PRIVACY_EVIDENCE_RECEIPTS {
            return Err(ApiError::Unprocessable(format!(
                "evidence_receipts must include at most {MAX_PRIVACY_EVIDENCE_RECEIPTS} entries"
            )));
        }
        record
            .evidence_receipts
            .push(validate_dpia_evidence_receipt(
                evidence_receipt,
                actor_name,
            )?);
        changed = true;
    }
    if changed {
        record.updated_at = now_rfc3339();
        record.updated_by = actor_name.to_owned();
    }
    Ok(changed)
}

fn apply_breach_playbook_patch(
    record: &mut BreachPlaybookRecord,
    req: PatchBreachPlaybook,
    actor_name: &str,
) -> Result<bool, ApiError> {
    let mut changed = false;
    if let Some(title) = req.title {
        record.title =
            required_privacy_control_segment(Some(title), "title", MAX_PRIVACY_CONTROL_NAME_CHARS)?;
        changed = true;
    }
    if let Some(scope) = req.scope {
        record.scope = required_privacy_control_segment(
            Some(scope),
            "scope",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(detection_channels) = req.detection_channels {
        record.detection_channels =
            sanitized_privacy_control_list(detection_channels, "detection_channels", true)?;
        changed = true;
    }
    if let Some(containment_steps) = req.containment_steps {
        record.containment_steps =
            sanitized_privacy_control_list(containment_steps, "containment_steps", true)?;
        changed = true;
    }
    if let Some(notification_roles) = req.notification_roles {
        record.notification_roles =
            sanitized_privacy_control_list(notification_roles, "notification_roles", false)?;
        changed = true;
    }
    if let Some(authority_notification_window) = req.authority_notification_window {
        record.authority_notification_window = optional_sensitive_checked_text(
            Some(authority_notification_window),
            "authority_notification_window",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(subject_notification_guidance) = req.subject_notification_guidance {
        record.subject_notification_guidance = optional_sensitive_checked_text(
            Some(subject_notification_guidance),
            "subject_notification_guidance",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(risk_level) = req.risk_level {
        record.risk_level = PrivacyRiskLevel::parse(&risk_level)?;
        changed = true;
    }
    if let Some(status) = req.status {
        record.status = PrivacyRecordStatus::parse(&status)?;
        changed = true;
    }
    if let Some(review_notes) = req.review_notes {
        record.review_notes = optional_sensitive_checked_text(
            Some(review_notes),
            "review_notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(evidence_receipt) = req.evidence_receipt {
        if record.evidence_receipts.len() >= MAX_PRIVACY_EVIDENCE_RECEIPTS {
            return Err(ApiError::Unprocessable(format!(
                "evidence_receipts must include at most {MAX_PRIVACY_EVIDENCE_RECEIPTS} entries"
            )));
        }
        record
            .evidence_receipts
            .push(validate_breach_evidence_receipt(
                evidence_receipt,
                actor_name,
            )?);
        changed = true;
    }
    if changed {
        record.updated_at = now_rfc3339();
        record.updated_by = actor_name.to_owned();
    }
    Ok(changed)
}

fn apply_transfer_control_patch(
    record: &mut TransferControlRecord,
    req: PatchTransferControl,
    actor_name: &str,
) -> Result<bool, ApiError> {
    let mut changed = false;
    if let Some(name) = req.name {
        record.name =
            required_privacy_control_segment(Some(name), "name", MAX_PRIVACY_CONTROL_NAME_CHARS)?;
        changed = true;
    }
    if let Some(purpose) = req.purpose {
        record.purpose = required_sensitive_checked_text(
            Some(purpose),
            "purpose",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(legal_basis) = req.legal_basis {
        record.legal_basis = required_sensitive_checked_text(
            Some(legal_basis),
            "legal_basis",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(data_categories) = req.data_categories {
        record.data_categories =
            sanitized_privacy_control_list(data_categories, "data_categories", true)?;
        changed = true;
    }
    if let Some(recipient) = req.recipient {
        record.recipient = required_privacy_control_segment(
            Some(recipient),
            "recipient",
            MAX_PRIVACY_CONTROL_NAME_CHARS,
        )?;
        changed = true;
    }
    if let Some(destination_country) = req.destination_country {
        record.destination_country = required_privacy_control_segment(
            Some(destination_country),
            "destination_country",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(transfer_mechanism) = req.transfer_mechanism {
        record.transfer_mechanism = required_privacy_control_segment(
            Some(transfer_mechanism),
            "transfer_mechanism",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(safeguards) = req.safeguards {
        record.safeguards = sanitized_privacy_control_list(safeguards, "safeguards", true)?;
        changed = true;
    }
    if let Some(risk_level) = req.risk_level {
        record.risk_level = PrivacyRiskLevel::parse(&risk_level)?;
        changed = true;
    }
    if let Some(status) = req.status {
        record.status = PrivacyRecordStatus::parse(&status)?;
        changed = true;
    }
    if let Some(review_notes) = req.review_notes {
        record.review_notes = optional_sensitive_checked_text(
            Some(review_notes),
            "review_notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(evidence_receipt) = req.evidence_receipt {
        if record.evidence_receipts.len() >= MAX_PRIVACY_EVIDENCE_RECEIPTS {
            return Err(ApiError::Unprocessable(format!(
                "evidence_receipts must include at most {MAX_PRIVACY_EVIDENCE_RECEIPTS} entries"
            )));
        }
        record
            .evidence_receipts
            .push(validate_transfer_evidence_receipt(
                evidence_receipt,
                actor_name,
            )?);
        changed = true;
    }
    if changed {
        record.updated_at = now_rfc3339();
        record.updated_by = actor_name.to_owned();
    }
    Ok(changed)
}

fn apply_retention_policy_patch(
    record: &mut RetentionPolicyRecord,
    req: PatchRetentionPolicy,
    actor_name: &str,
) -> Result<bool, ApiError> {
    let mut changed = false;
    if let Some(name) = req.name {
        record.name = required_retention_segment(Some(name), "name", MAX_RETENTION_NAME_CHARS)?;
        changed = true;
    }
    if let Some(scope) = req.scope {
        record.scope = required_retention_segment(Some(scope), "scope", MAX_RETENTION_FIELD_CHARS)?;
        changed = true;
    }
    if let Some(category) = req.category {
        record.category =
            required_retention_segment(Some(category), "category", MAX_RETENTION_FIELD_CHARS)?;
        changed = true;
    }
    if let Some(schedule_id) = req.schedule_id {
        record.schedule_id = required_retention_segment(
            Some(schedule_id),
            "schedule_id",
            MAX_RETENTION_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(retention_period) = req.retention_period {
        record.retention_period = required_retention_segment(
            Some(retention_period),
            "retention_period",
            MAX_RETENTION_FIELD_CHARS,
        )?;
        changed = true;
    }
    if let Some(legal_basis) = req.legal_basis {
        record.legal_basis = required_sensitive_checked_text(
            Some(legal_basis),
            "legal_basis",
            MAX_RETENTION_TEXT_CHARS,
        )?;
        changed = true;
    }
    if let Some(disposal_action) = req.disposal_action {
        record.disposal_action = RetentionDisposalAction::parse(&disposal_action)?;
        changed = true;
    }
    if let Some(status) = req.status {
        record.status = RetentionPolicyStatus::parse(&status)?;
        changed = true;
    }
    if let Some(active) = req.active {
        record.active = active;
        changed = true;
    }
    if let Some(notes) = req.notes {
        record.notes =
            optional_sensitive_checked_text(Some(notes), "notes", MAX_RETENTION_TEXT_CHARS)?;
        changed = true;
    }
    if changed {
        record.updated_at = now_rfc3339();
        record.updated_by = actor_name.to_owned();
    }
    Ok(changed)
}

fn validate_retention_execution_request(
    raw: Option<RetentionExecutionRequest>,
) -> Result<Option<ValidatedRetentionExecutionRequest>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let requested_policy_id = raw
        .requested_policy_id
        .map(|value| parse_retention_policy_id(value, "execution_request.requested_policy_id"))
        .transpose()?;
    let execution_intent = raw
        .execution_mode
        .as_deref()
        .map(RetentionExecutionIntent::parse)
        .transpose()?
        .unwrap_or(RetentionExecutionIntent::ReviewOnly);
    let operator_notes = optional_sensitive_checked_text(
        raw.operator_notes,
        "execution_request.operator_notes",
        MAX_RETENTION_TEXT_CHARS,
    )?;
    let evidence = sanitize_retention_execution_evidence(raw.evidence)?;
    let approval = validate_retention_execution_approval(raw.approval)?;
    Ok(Some(ValidatedRetentionExecutionRequest {
        requested_policy_id,
        execution_intent,
        operator_notes,
        evidence,
        approval,
    }))
}

fn validate_retention_execution_approval(
    raw: Option<RetentionExecutionApprovalInput>,
) -> Result<Option<RetentionExecutionApproval>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let approved_at = optional_rfc3339_string(
        raw.approved_at,
        "execution_request.approval.approved_at",
        MAX_RETENTION_FIELD_CHARS,
    )?;
    Ok(Some(RetentionExecutionApproval {
        approval_reference: required_retention_segment(
            raw.approval_reference,
            "execution_request.approval.approval_reference",
            MAX_RETENTION_FIELD_CHARS,
        )?,
        policy_id: parse_retention_policy_id(
            required_retention_segment(
                raw.policy_id,
                "execution_request.approval.policy_id",
                MAX_RETENTION_FIELD_CHARS,
            )?,
            "execution_request.approval.policy_id",
        )?
        .to_string(),
        disposal_action: raw
            .disposal_action
            .as_deref()
            .ok_or_else(|| {
                ApiError::Unprocessable(
                    "execution_request.approval.disposal_action is required".to_owned(),
                )
            })
            .and_then(RetentionDisposalAction::parse)?,
        approved_by: required_retention_segment(
            raw.approved_by,
            "execution_request.approval.approved_by",
            MAX_RETENTION_FIELD_CHARS,
        )?,
        approved_at,
    }))
}

fn sanitize_retention_execution_evidence(
    raw: Option<Vec<RetentionExecutionEvidenceInput>>,
) -> Result<Vec<RetentionOperatorEvidence>, ApiError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS {
        return Err(ApiError::Unprocessable(format!(
            "execution_request.evidence must include at most {MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS} entries"
        )));
    }

    raw.into_iter()
        .map(|item| {
            let label = required_retention_segment(
                item.label,
                "execution_request.evidence.label",
                MAX_RETENTION_EXECUTION_EVIDENCE_LABEL_CHARS,
            )?;
            let value = required_sensitive_checked_text(
                item.value,
                "execution_request.evidence.value",
                MAX_RETENTION_TEXT_CHARS,
            )?;
            Ok(RetentionOperatorEvidence { label, value })
        })
        .collect()
}

fn validate_retention_review_closure(
    raw: RetentionReviewClosureRequest,
) -> Result<ValidatedRetentionReviewClosure, ApiError> {
    reject_true_flag(
        raw.destructive_disposal_completed,
        "destructive_disposal_completed",
        "destructive disposal completion",
    )?;
    reject_true_flag(
        raw.full_erasure_completed,
        "full_erasure_completed",
        "full erasure completion",
    )?;
    reject_true_flag(
        raw.legal_hold_mutated,
        "legal_hold_mutated",
        "legal hold mutation",
    )?;
    reject_true_flag(
        raw.retention_policy_mutated,
        "retention_policy_mutated",
        "retention policy mutation",
    )?;

    let decision = raw
        .review_closure_decision
        .as_deref()
        .ok_or_else(|| ApiError::Unprocessable("review_closure_decision is required".to_owned()))
        .and_then(RetentionReviewClosureDecision::parse)?;
    let note = clean_optional_bounded(
        raw.review_closure_note,
        "review_closure_note",
        MAX_RETENTION_TEXT_CHARS,
    )?;
    if let Some(note) = &note {
        reject_retention_review_closure_claims(note, "review_closure_note")?;
    }
    let evidence = sanitize_retention_review_closure_evidence(raw.review_closure_evidence)?;
    if note.is_none() && evidence.is_empty() {
        return Err(ApiError::Unprocessable(
            "review_closure_note or review_closure_evidence is required".to_owned(),
        ));
    }

    Ok(ValidatedRetentionReviewClosure {
        decision,
        note,
        evidence,
    })
}

fn validate_retention_candidate_resolution(
    raw: RetentionCandidateResolutionRequest,
    candidate: &RetentionDueCandidate,
) -> Result<ValidatedRetentionCandidateResolution, ApiError> {
    let candidate_fingerprint = required_retention_segment(
        raw.candidate_fingerprint,
        "candidate_fingerprint",
        MAX_RETENTION_FIELD_CHARS,
    )?;
    if candidate_fingerprint != candidate.candidate_fingerprint {
        return Err(ApiError::Unprocessable(
            "candidate_fingerprint is stale for the current due candidate".to_owned(),
        ));
    }
    reject_true_flag(
        raw.destructive_disposal_completed,
        "destructive_disposal_completed",
        "destructive disposal completion",
    )?;
    reject_true_flag(
        raw.disposal_completed,
        "disposal_completed",
        "disposal completion",
    )?;
    reject_true_flag(
        raw.full_erasure_completed,
        "full_erasure_completed",
        "full erasure completion",
    )?;
    reject_true_flag(
        raw.erasure_completed,
        "erasure_completed",
        "erasure completion",
    )?;
    reject_true_flag(
        raw.legal_hold_mutated,
        "legal_hold_mutated",
        "legal hold mutation",
    )?;
    reject_true_flag(
        raw.legal_hold_resolved,
        "legal_hold_resolved",
        "legal hold resolution",
    )?;
    reject_true_flag(
        raw.retention_policy_mutated,
        "retention_policy_mutated",
        "retention policy mutation",
    )?;
    reject_true_flag(
        raw.retention_policy_changed,
        "retention_policy_changed",
        "retention policy change",
    )?;
    reject_true_flag(
        raw.legal_completion_claimed,
        "legal_completion_claimed",
        "legal completion",
    )?;
    reject_true_flag(
        raw.legal_disposal_completed,
        "legal_disposal_completed",
        "legal disposal completion",
    )?;

    let disposition = raw
        .disposition
        .as_deref()
        .ok_or_else(|| ApiError::Unprocessable("disposition is required".to_owned()))
        .and_then(RetentionCandidateDisposition::parse)?;
    validate_retention_candidate_disposition(candidate, disposition)?;
    let note = clean_optional_bounded(raw.note, "note", MAX_RETENTION_TEXT_CHARS)?;
    if let Some(note) = &note {
        reject_retention_candidate_resolution_claims(note, "note")?;
    }
    let evidence = sanitize_retention_candidate_resolution_evidence(raw.evidence)?;
    if note.is_none() && evidence.is_empty() {
        return Err(ApiError::Unprocessable(
            "note or evidence is required".to_owned(),
        ));
    }

    Ok(ValidatedRetentionCandidateResolution {
        disposition,
        note,
        evidence,
    })
}

fn sanitize_retention_review_closure_evidence(
    raw: Option<Vec<RetentionReviewClosureEvidenceInput>>,
) -> Result<Vec<RetentionOperatorEvidence>, ApiError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS {
        return Err(ApiError::Unprocessable(format!(
            "review_closure_evidence must include at most {MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS} entries"
        )));
    }

    raw.into_iter()
        .map(|item| {
            let label = required_retention_segment(
                item.label,
                "review_closure_evidence.label",
                MAX_RETENTION_EXECUTION_EVIDENCE_LABEL_CHARS,
            )?;
            reject_retention_review_closure_claims(&label, "review_closure_evidence.label")?;
            let value = required_sensitive_checked_text(
                item.value,
                "review_closure_evidence.value",
                MAX_RETENTION_TEXT_CHARS,
            )?;
            reject_retention_review_closure_claims(&value, "review_closure_evidence.value")?;
            Ok(RetentionOperatorEvidence { label, value })
        })
        .collect()
}

fn sanitize_retention_candidate_resolution_evidence(
    raw: Option<Vec<RetentionReviewClosureEvidenceInput>>,
) -> Result<Vec<RetentionOperatorEvidence>, ApiError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS {
        return Err(ApiError::Unprocessable(format!(
            "evidence must include at most {MAX_RETENTION_EXECUTION_EVIDENCE_ITEMS} entries"
        )));
    }

    raw.into_iter()
        .map(|item| {
            let label = required_retention_segment(
                item.label,
                "evidence.label",
                MAX_RETENTION_EXECUTION_EVIDENCE_LABEL_CHARS,
            )?;
            reject_retention_candidate_resolution_claims(&label, "evidence.label")?;
            let value = required_sensitive_checked_text(
                item.value,
                "evidence.value",
                MAX_RETENTION_TEXT_CHARS,
            )?;
            reject_retention_candidate_resolution_claims(&value, "evidence.value")?;
            Ok(RetentionOperatorEvidence { label, value })
        })
        .collect()
}

fn validate_retention_candidate_disposition(
    candidate: &RetentionDueCandidate,
    disposition: RetentionCandidateDisposition,
) -> Result<(), ApiError> {
    if disposition == RetentionCandidateDisposition::EvidenceAcknowledged
        && retention_candidate_requires_follow_up_resolution(candidate)
    {
        return Err(ApiError::Unprocessable(
            "blocked, destructive, legal-hold, or policy-blocked due candidates can only record follow-up evidence"
                .to_owned(),
        ));
    }
    Ok(())
}

fn retention_candidate_requires_follow_up_resolution(candidate: &RetentionDueCandidate) -> bool {
    candidate.status == retention_execution_status_wire(RetentionExecutionStatus::Blocked)
        || candidate.destructive_action
        || !candidate.legal_hold_blockers.is_empty()
        || !candidate.blockers.is_empty()
        || !candidate.findings.is_empty()
}

fn build_retention_execution_record(
    actor_name: &str,
    candidate: &RetentionDryRunCandidate,
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
    matches: &[RetentionDryRunMatch],
    prior_execution_records: &HashMap<String, RetentionExecutionRecord>,
    request: ValidatedRetentionExecutionRequest,
) -> RetentionExecutionRecord {
    let requested_policy =
        retention_requested_policy(candidate, records, request.requested_policy_id);
    let legal_hold_blockers = retention_legal_hold_blockers(candidate, records);
    let prior_execution =
        retention_prior_bounded_execution(candidate, &requested_policy, prior_execution_records);
    let (outcome, block_reason) = retention_execution_decision(
        candidate,
        &requested_policy,
        &legal_hold_blockers,
        request.execution_intent,
        request.approval.as_ref(),
        prior_execution.as_ref(),
    );
    let workflow = retention_operator_workflow(
        &requested_policy,
        &legal_hold_blockers,
        outcome,
        block_reason,
    );
    let execution_result = retention_execution_result(RetentionExecutionResultContext {
        actor_name,
        candidate,
        requested_policy: &requested_policy,
        outcome,
        workflow: &workflow,
        execution_intent: request.execution_intent,
        approval: request.approval.as_ref(),
        prior_execution_id: prior_execution.as_ref(),
    });

    RetentionExecutionRecord {
        id: Uuid::new_v4().to_string(),
        requested_at: now_rfc3339(),
        actor: actor_name.to_owned(),
        execution_intent: request.execution_intent,
        execution_status: retention_execution_status(outcome),
        operator_review_decision: retention_operator_review_decision(outcome),
        decision_state: RetentionExecutionDecisionState::Open,
        review_closure_decision: None,
        review_closure_evidence: Vec::new(),
        review_closed_by: None,
        review_closed_at: None,
        review_closure_note: None,
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        legal_hold_mutated: false,
        retention_policy_mutated: false,
        requested_policy,
        candidate: candidate.clone(),
        matched_records_summary: retention_matched_records_summary(candidate, matches),
        legal_hold_blockers,
        operator_notes: request.operator_notes,
        audit_evidence: request.evidence,
        approval: request.approval,
        outcome,
        block_reason: block_reason.to_owned(),
        evidence_state: retention_execution_evidence_state(outcome),
        evidence_next_step: retention_execution_evidence_next_step(outcome, &workflow.next_step),
        workflow,
        would_execute: matches!(
            outcome,
            RetentionExecutionOutcome::BoundedArchiveRecorded
                | RetentionExecutionOutcome::BoundedNoActionRecorded
        ),
        execution_result,
    }
}

fn retention_requested_policy(
    candidate: &RetentionDryRunCandidate,
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
    requested_policy_id: Option<RetentionPolicyId>,
) -> RetentionExecutionRequestedPolicy {
    let Some(id) = requested_policy_id else {
        return missing_retention_requested_policy(None);
    };
    let Some(record) = records.get(&id) else {
        return missing_retention_requested_policy(Some(id.to_string()));
    };
    let matches_candidate = retention_value_matches(&record.scope, &candidate.scope)
        && retention_value_matches(&record.category, &candidate.category);
    let stale = !record.active || record.status != RetentionPolicyStatus::Active;
    RetentionExecutionRequestedPolicy {
        id: Some(id.to_string()),
        found: true,
        name: Some(record.name.clone()),
        scope: Some(record.scope.clone()),
        category: Some(record.category.clone()),
        schedule_id: Some(record.schedule_id.clone()),
        retention_period: Some(record.retention_period.clone()),
        disposal_action: Some(record.disposal_action),
        status: Some(record.status),
        active: Some(record.active),
        stale,
        matches_candidate,
        destructive_action: record.disposal_action.is_destructive(),
    }
}

fn missing_retention_requested_policy(id: Option<String>) -> RetentionExecutionRequestedPolicy {
    RetentionExecutionRequestedPolicy {
        id,
        found: false,
        name: None,
        scope: None,
        category: None,
        schedule_id: None,
        retention_period: None,
        disposal_action: None,
        status: None,
        active: None,
        stale: false,
        matches_candidate: false,
        destructive_action: false,
    }
}

fn retention_legal_hold_blockers(
    candidate: &RetentionDryRunCandidate,
    records: &HashMap<RetentionPolicyId, RetentionPolicyRecord>,
) -> Vec<RetentionLegalHoldBlocker> {
    let mut blockers: Vec<&RetentionPolicyRecord> = records
        .values()
        .filter(|record| {
            record.disposal_action == RetentionDisposalAction::LegalHold
                && retention_policy_applies(record, &candidate.scope, &candidate.category)
        })
        .collect();
    blockers.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.0.cmp(&b.id.0)));
    blockers
        .into_iter()
        .map(|record| RetentionLegalHoldBlocker {
            policy_id: record.id.to_string(),
            name: record.name.clone(),
            schedule_id: record.schedule_id.clone(),
            retention_period: record.retention_period.clone(),
            reason: "active legal hold policy matches the candidate record".to_owned(),
        })
        .collect()
}

fn retention_matched_records_summary(
    candidate: &RetentionDryRunCandidate,
    matches: &[RetentionDryRunMatch],
) -> RetentionMatchedRecordsSummary {
    RetentionMatchedRecordsSummary {
        scope: candidate.scope.clone(),
        category: candidate.category.clone(),
        record_id: candidate.record_id.clone(),
        record_count: usize::from(candidate.record_id.is_some()),
        policy_match_count: matches.len(),
        destructive_policy_count: matches
            .iter()
            .filter(|record| record.destructive_action)
            .count(),
        policy_ids: matches
            .iter()
            .map(|record| record.policy_id.clone())
            .collect(),
    }
}

fn retention_prior_bounded_execution(
    candidate: &RetentionDryRunCandidate,
    requested_policy: &RetentionExecutionRequestedPolicy,
    prior_execution_records: &HashMap<String, RetentionExecutionRecord>,
) -> Option<String> {
    retention_prior_bounded_execution_record(
        candidate,
        requested_policy.id.as_deref()?,
        prior_execution_records,
    )
    .map(|record| record.id.clone())
}

fn retention_prior_bounded_due_candidate_projection(
    candidate: &RetentionDryRunCandidate,
    policy: &RetentionPolicyRecord,
    prior_execution_records: &HashMap<String, RetentionExecutionRecord>,
) -> Option<RetentionDueCandidatePriorExecution> {
    retention_prior_bounded_execution_record(
        candidate,
        &policy.id.to_string(),
        prior_execution_records,
    )
    .map(|record| RetentionDueCandidatePriorExecution {
        execution_id: record.id.clone(),
        execution_status: retention_execution_status_wire(record.execution_status).to_owned(),
        outcome: retention_execution_outcome_wire(record.outcome).to_owned(),
        evidence_state: retention_prior_bounded_evidence_state(record.outcome),
        evidence_next_step: retention_prior_bounded_due_candidate_next_step(record.outcome)
            .to_owned(),
        requested_at: record.requested_at.clone(),
        executed_at: record.execution_result.executed_at.clone(),
        bounded_executor: record.execution_result.bounded_executor,
        targets_acted_count: record.execution_result.targets_acted.len(),
        destructive_disposal_completed: record.execution_result.destructive_disposal_completed,
        full_erasure_completed: record.execution_result.full_erasure_completed,
        next_step: retention_prior_bounded_due_candidate_next_step(record.outcome).to_owned(),
    })
}

fn retention_due_candidate_evidence_progression(
    status: &str,
    prior_execution: Option<&RetentionDueCandidatePriorExecution>,
    next_step: &str,
    outcome: RetentionExecutionOutcome,
) -> (RetentionEvidenceState, String) {
    if status == retention_execution_status_wire(RetentionExecutionStatus::Blocked) {
        return (RetentionEvidenceState::Blocked, next_step.to_owned());
    }
    if let Some(prior_execution) = prior_execution {
        return (
            prior_execution.evidence_state,
            prior_execution.evidence_next_step.clone(),
        );
    }
    (
        retention_execution_evidence_state(outcome),
        retention_execution_evidence_next_step(outcome, next_step),
    )
}

fn retention_prior_bounded_due_candidate_next_step(
    outcome: RetentionExecutionOutcome,
) -> &'static str {
    match outcome {
        RetentionExecutionOutcome::BoundedArchiveRecorded => {
            RETENTION_PRIOR_BOUNDED_ARCHIVE_NEXT_STEP
        }
        RetentionExecutionOutcome::BoundedNoActionRecorded => {
            RETENTION_PRIOR_BOUNDED_NO_ACTION_NEXT_STEP
        }
        _ => RETENTION_PRIOR_BOUNDED_GENERIC_NEXT_STEP,
    }
}

fn retention_prior_bounded_evidence_state(
    outcome: RetentionExecutionOutcome,
) -> RetentionEvidenceState {
    match outcome {
        RetentionExecutionOutcome::BoundedArchiveRecorded => {
            RetentionEvidenceState::BoundedArchiveRecorded
        }
        RetentionExecutionOutcome::BoundedNoActionRecorded => {
            RetentionEvidenceState::BoundedNoActionRecorded
        }
        _ => RetentionEvidenceState::PriorBoundedEvidenceAvailable,
    }
}

fn retention_prior_bounded_execution_record<'a>(
    candidate: &RetentionDryRunCandidate,
    requested_policy_id: &str,
    prior_execution_records: &'a HashMap<String, RetentionExecutionRecord>,
) -> Option<&'a RetentionExecutionRecord> {
    prior_execution_records
        .values()
        .filter(|record| {
            retention_prior_execution_matches_candidate(record, candidate, requested_policy_id)
                && retention_execution_record_is_safe_bounded_prior(record)
        })
        .min_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)))
}

fn retention_prior_execution_matches_candidate(
    record: &RetentionExecutionRecord,
    candidate: &RetentionDryRunCandidate,
    requested_policy_id: &str,
) -> bool {
    record.candidate.scope == candidate.scope
        && record.candidate.category == candidate.category
        && record.candidate.record_id == candidate.record_id
        && record.requested_policy.id.as_deref() == Some(requested_policy_id)
}

fn retention_execution_record_is_safe_bounded_prior(record: &RetentionExecutionRecord) -> bool {
    record.execution_status == RetentionExecutionStatus::Executed
        && matches!(
            record.outcome,
            RetentionExecutionOutcome::BoundedArchiveRecorded
                | RetentionExecutionOutcome::BoundedNoActionRecorded
        )
        && record.execution_result.bounded_executor
        && !record.execution_result.destructive_disposal_completed
        && !record.execution_result.full_erasure_completed
        && !record.execution_result.targets_acted.is_empty()
}

fn retention_existing_awaiting_review_execution(
    candidate: &RetentionDryRunCandidate,
    request: &ValidatedRetentionExecutionRequest,
    prior_execution_records: &HashMap<String, RetentionExecutionRecord>,
) -> Option<RetentionExecutionRecord> {
    if request.execution_intent != RetentionExecutionIntent::ReviewOnly {
        return None;
    }
    let requested_policy_id = request.requested_policy_id.map(|id| id.to_string());
    prior_execution_records
        .values()
        .filter(|record| {
            record.execution_intent == RetentionExecutionIntent::ReviewOnly
                && record.execution_status == RetentionExecutionStatus::AwaitingReview
                && record.decision_state == RetentionExecutionDecisionState::Open
                && record.candidate.scope == candidate.scope
                && record.candidate.category == candidate.category
                && record.candidate.record_id == candidate.record_id
                && record.requested_policy.id.as_deref() == requested_policy_id.as_deref()
        })
        .min_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)))
        .cloned()
}

fn validate_retention_review_closure_decision_for_record(
    record: &RetentionExecutionRecord,
    decision: RetentionReviewClosureDecision,
) -> Result<(), ApiError> {
    let expected = retention_review_closure_decision_for_outcome(record.outcome);
    if decision == expected {
        Ok(())
    } else {
        Err(ApiError::Unprocessable(format!(
            "review_closure_decision must be {} for this retention execution outcome",
            retention_review_closure_decision_wire(expected)
        )))
    }
}

fn retention_review_closure_decision_for_outcome(
    outcome: RetentionExecutionOutcome,
) -> RetentionReviewClosureDecision {
    match outcome {
        RetentionExecutionOutcome::ManualReviewRequired => {
            RetentionReviewClosureDecision::ReviewEvidenceAcknowledged
        }
        RetentionExecutionOutcome::BoundedArchiveRecorded
        | RetentionExecutionOutcome::BoundedNoActionRecorded
        | RetentionExecutionOutcome::AlreadyExecuted => {
            RetentionReviewClosureDecision::BoundedEvidenceAcknowledged
        }
        RetentionExecutionOutcome::BlockedMissingPolicy
        | RetentionExecutionOutcome::BlockedStalePolicy
        | RetentionExecutionOutcome::BlockedPolicyMismatch
        | RetentionExecutionOutcome::BlockedLegalHold
        | RetentionExecutionOutcome::BlockedDestructiveAction
        | RetentionExecutionOutcome::BlockedApprovalMismatch
        | RetentionExecutionOutcome::BlockedMissingTarget => {
            RetentionReviewClosureDecision::BlockedEvidenceAcknowledged
        }
    }
}

fn retention_review_closure_matches(
    record: &RetentionExecutionRecord,
    closure: &ValidatedRetentionReviewClosure,
) -> bool {
    record.review_closure_decision == Some(closure.decision)
        && record.review_closure_note == closure.note
        && record.review_closure_evidence == closure.evidence
        && !record.destructive_disposal_completed
        && !record.full_erasure_completed
        && !record.legal_hold_mutated
        && !record.retention_policy_mutated
}

fn apply_retention_review_closure(
    record: &mut RetentionExecutionRecord,
    closure: ValidatedRetentionReviewClosure,
    actor_name: &str,
) {
    record.decision_state = RetentionExecutionDecisionState::ReviewClosed;
    record.review_closure_decision = Some(closure.decision);
    record.review_closure_evidence = closure.evidence;
    record.review_closed_by = Some(actor_name.to_owned());
    record.review_closed_at = Some(now_rfc3339());
    record.review_closure_note = closure.note;
    record.destructive_disposal_completed = false;
    record.full_erasure_completed = false;
    record.legal_hold_mutated = false;
    record.retention_policy_mutated = false;
}

fn retention_review_closure_ledger_event(
    record: &RetentionExecutionRecord,
) -> RetentionReviewClosureLedgerEvent<'_> {
    RetentionReviewClosureLedgerEvent {
        execution_id: &record.id,
        decision_state: record.decision_state,
        review_closure_decision: record.review_closure_decision,
        review_closure_evidence: &record.review_closure_evidence,
        review_closed_by: record.review_closed_by.as_deref(),
        review_closed_at: record.review_closed_at.as_deref(),
        review_closure_note: record.review_closure_note.as_deref(),
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        legal_hold_mutated: false,
        retention_policy_mutated: false,
    }
}

fn retention_execution_decision(
    candidate: &RetentionDryRunCandidate,
    requested_policy: &RetentionExecutionRequestedPolicy,
    legal_hold_blockers: &[RetentionLegalHoldBlocker],
    execution_intent: RetentionExecutionIntent,
    approval: Option<&RetentionExecutionApproval>,
    prior_execution_id: Option<&String>,
) -> (RetentionExecutionOutcome, &'static str) {
    if !requested_policy.found {
        return (
            RetentionExecutionOutcome::BlockedMissingPolicy,
            "requested retention policy is missing; execution requires operator review",
        );
    }
    if requested_policy.stale {
        return (
            RetentionExecutionOutcome::BlockedStalePolicy,
            "requested retention policy is not active; execution requires operator review",
        );
    }
    if !requested_policy.matches_candidate {
        return (
            RetentionExecutionOutcome::BlockedPolicyMismatch,
            "requested retention policy does not match the candidate scope/category",
        );
    }
    if !legal_hold_blockers.is_empty() {
        return (
            RetentionExecutionOutcome::BlockedLegalHold,
            "active legal hold blocks retention execution",
        );
    }
    if approval
        .is_some_and(|approval| !retention_execution_approval_matches(requested_policy, approval))
    {
        return (
            RetentionExecutionOutcome::BlockedApprovalMismatch,
            "provided approval metadata does not match the requested policy/action",
        );
    }
    if execution_intent == RetentionExecutionIntent::ExecuteSupported
        && candidate.record_id.is_none()
    {
        return (
            RetentionExecutionOutcome::BlockedMissingTarget,
            "bounded execution requires a concrete record_id target",
        );
    }
    if requested_policy.destructive_action {
        return (
            RetentionExecutionOutcome::BlockedDestructiveAction,
            if execution_intent == RetentionExecutionIntent::ExecuteSupported && approval.is_none()
            {
                "destructive disposal requires matching approval and is not executed by this API"
            } else {
                "delete/anonymize execution is not enabled in this guarded slice"
            },
        );
    }
    if let Some(action) = requested_policy.disposal_action
        && execution_intent == RetentionExecutionIntent::ExecuteSupported
    {
        if prior_execution_id.is_some() {
            return (
                RetentionExecutionOutcome::AlreadyExecuted,
                "bounded retention action was already recorded for this target and policy",
            );
        }
        return match action {
            RetentionDisposalAction::Archive => (
                RetentionExecutionOutcome::BoundedArchiveRecorded,
                "bounded archive evidence recorded for the retention target",
            ),
            RetentionDisposalAction::NoAction => (
                RetentionExecutionOutcome::BoundedNoActionRecorded,
                "bounded no-action evidence recorded for the retention target",
            ),
            RetentionDisposalAction::Review => (
                RetentionExecutionOutcome::ManualReviewRequired,
                "retention policy requires manual review before any separate operational action",
            ),
            RetentionDisposalAction::LegalHold
            | RetentionDisposalAction::Delete
            | RetentionDisposalAction::Anonymize => (
                RetentionExecutionOutcome::BlockedDestructiveAction,
                "retention action is not executable in this guarded slice",
            ),
        };
    }
    (
        RetentionExecutionOutcome::ManualReviewRequired,
        "retention execution request is recorded for manual review only",
    )
}

fn retention_execution_approval_matches(
    requested_policy: &RetentionExecutionRequestedPolicy,
    approval: &RetentionExecutionApproval,
) -> bool {
    requested_policy.id.as_deref() == Some(approval.policy_id.as_str())
        && requested_policy.disposal_action == Some(approval.disposal_action)
}

fn retention_operator_workflow(
    requested_policy: &RetentionExecutionRequestedPolicy,
    legal_hold_blockers: &[RetentionLegalHoldBlocker],
    outcome: RetentionExecutionOutcome,
    block_reason: &str,
) -> RetentionOperatorWorkflow {
    let mut blockers = Vec::new();
    match outcome {
        RetentionExecutionOutcome::BlockedMissingPolicy => blockers.push(retention_blocker(
            "requested_policy_required",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::BlockedStalePolicy => blockers.push(retention_blocker(
            "requested_policy_active",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::BlockedPolicyMismatch => blockers.push(retention_blocker(
            "requested_policy_scope_match",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::BlockedLegalHold => {
            blockers.extend(legal_hold_blockers.iter().map(|blocker| {
                retention_blocker(
                    "legal_hold_release",
                    &blocker.reason,
                    Some(blocker.policy_id.clone()),
                )
            }));
        }
        RetentionExecutionOutcome::BlockedDestructiveAction => blockers.push(retention_blocker(
            "destructive_action_disabled",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::BlockedApprovalMismatch => blockers.push(retention_blocker(
            "execution_approval_match",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::BlockedMissingTarget => blockers.push(retention_blocker(
            "candidate_record_required",
            block_reason,
            requested_policy.id.clone(),
        )),
        RetentionExecutionOutcome::ManualReviewRequired
        | RetentionExecutionOutcome::BoundedArchiveRecorded
        | RetentionExecutionOutcome::BoundedNoActionRecorded
        | RetentionExecutionOutcome::AlreadyExecuted => {}
    }

    let mut required_approvals = Vec::new();
    if matches!(
        outcome,
        RetentionExecutionOutcome::BlockedMissingPolicy
            | RetentionExecutionOutcome::BlockedStalePolicy
            | RetentionExecutionOutcome::BlockedPolicyMismatch
            | RetentionExecutionOutcome::BlockedApprovalMismatch
    ) {
        required_approvals.push(retention_required_approval(
            "policy_register_review",
            "privacy_or_settings_manager",
            "confirm an active matching retention policy before any follow-up review",
        ));
    } else {
        required_approvals.push(retention_required_approval(
            "retention_manual_review",
            "privacy_or_settings_manager",
            "approve the retained evidence before any separate operational action",
        ));
    }

    if !legal_hold_blockers.is_empty() {
        required_approvals.push(retention_required_approval(
            "legal_hold_owner_release",
            "legal_hold_owner",
            "resolve matching legal hold policies before disposal review can continue",
        ));
    }

    if requested_policy.destructive_action {
        required_approvals.push(retention_required_approval(
            "destructive_disposal_governance",
            "external_governance_process",
            "destructive disposal is outside this API and requires separate approval",
        ));
    }

    let status = if blockers.is_empty() {
        RetentionOperatorWorkflowStatus::AwaitingManualReview
    } else {
        RetentionOperatorWorkflowStatus::Blocked
    };
    let next_step = match outcome {
        RetentionExecutionOutcome::BlockedMissingPolicy
        | RetentionExecutionOutcome::BlockedStalePolicy
        | RetentionExecutionOutcome::BlockedPolicyMismatch => {
            "Select or update an active matching retention policy; no disposal has been executed."
        }
        RetentionExecutionOutcome::BlockedLegalHold => {
            "Resolve the legal hold approval before continuing; no disposal has been executed."
        }
        RetentionExecutionOutcome::BlockedDestructiveAction => {
            "Record separate governance approval before any external destructive process; this API will not execute it."
        }
        RetentionExecutionOutcome::BlockedApprovalMismatch => {
            "Correct the approval metadata so it matches the requested policy/action; no disposal has been executed."
        }
        RetentionExecutionOutcome::BlockedMissingTarget => {
            "Provide a concrete record_id before bounded execution; no disposal has been executed."
        }
        RetentionExecutionOutcome::ManualReviewRequired => {
            "Review the retained evidence for manual approval; no disposal has been executed."
        }
        RetentionExecutionOutcome::BoundedArchiveRecorded => {
            "Bounded archive evidence was recorded for this target; no source document deletion or GDPR erasure was performed."
        }
        RetentionExecutionOutcome::BoundedNoActionRecorded => {
            "Bounded no-action evidence was recorded for this target; no source document deletion or GDPR erasure was performed."
        }
        RetentionExecutionOutcome::AlreadyExecuted => {
            "A prior bounded execution already recorded this target/policy action; no duplicate action was recorded."
        }
    };

    RetentionOperatorWorkflow {
        status,
        blockers,
        required_approvals,
        next_step: next_step.to_owned(),
    }
}

fn retention_blocker(
    code: impl Into<String>,
    message: impl Into<String>,
    policy_id: Option<String>,
) -> RetentionWorkflowBlocker {
    RetentionWorkflowBlocker {
        code: code.into(),
        message: message.into(),
        policy_id,
    }
}

fn retention_required_approval(
    code: impl Into<String>,
    required_from: impl Into<String>,
    reason: impl Into<String>,
) -> RetentionRequiredApproval {
    RetentionRequiredApproval {
        code: code.into(),
        required_from: required_from.into(),
        reason: reason.into(),
    }
}

struct RetentionExecutionResultContext<'a> {
    actor_name: &'a str,
    candidate: &'a RetentionDryRunCandidate,
    requested_policy: &'a RetentionExecutionRequestedPolicy,
    outcome: RetentionExecutionOutcome,
    workflow: &'a RetentionOperatorWorkflow,
    execution_intent: RetentionExecutionIntent,
    approval: Option<&'a RetentionExecutionApproval>,
    prior_execution_id: Option<&'a String>,
}

fn retention_execution_result(
    ctx: RetentionExecutionResultContext<'_>,
) -> RetentionExecutionResult {
    let target = retention_execution_target(
        ctx.candidate,
        ctx.requested_policy,
        outcome_reason_code(ctx.outcome),
    );
    let mut targets_acted = Vec::new();
    let mut targets_skipped = Vec::new();
    let mut reason_codes = vec![outcome_reason_code(ctx.outcome).to_owned()];
    let mut blocker_metadata: Vec<RetentionExecutionBlockerMetadata> = ctx
        .workflow
        .blockers
        .iter()
        .map(|blocker| RetentionExecutionBlockerMetadata {
            code: blocker.code.clone(),
            detail: blocker.message.clone(),
            policy_id: blocker.policy_id.clone(),
        })
        .collect();

    let executed = matches!(
        ctx.outcome,
        RetentionExecutionOutcome::BoundedArchiveRecorded
            | RetentionExecutionOutcome::BoundedNoActionRecorded
    );
    if executed {
        targets_acted.push(target.clone());
    } else {
        targets_skipped.push(target);
    }

    if matches!(ctx.outcome, RetentionExecutionOutcome::AlreadyExecuted)
        && let Some(prior_execution_id) = ctx.prior_execution_id
    {
        reason_codes.push("prior_bounded_execution_found".to_owned());
        blocker_metadata.push(RetentionExecutionBlockerMetadata {
            code: "prior_bounded_execution".to_owned(),
            detail: format!("prior execution record {prior_execution_id} already acted"),
            policy_id: ctx.requested_policy.id.clone(),
        });
    }

    if ctx.requested_policy.destructive_action && ctx.approval.is_none() {
        reason_codes.push("destructive_disposal_approval_required".to_owned());
        blocker_metadata.push(RetentionExecutionBlockerMetadata {
            code: "destructive_disposal_approval_required".to_owned(),
            detail:
                "matching approval metadata is required before any external destructive process"
                    .to_owned(),
            policy_id: ctx.requested_policy.id.clone(),
        });
    } else if ctx.requested_policy.destructive_action {
        reason_codes.push("destructive_disposal_not_supported_by_api".to_owned());
    }

    if ctx.execution_intent == RetentionExecutionIntent::ReviewOnly {
        reason_codes.push("review_only_intent".to_owned());
    }

    RetentionExecutionResult {
        bounded_executor: true,
        executed_at: executed.then(now_rfc3339),
        executed_by: executed.then(|| ctx.actor_name.to_owned()),
        targets_considered: vec![retention_execution_target(
            ctx.candidate,
            ctx.requested_policy,
            "target_considered",
        )],
        targets_acted,
        targets_skipped,
        reason_codes,
        next_step: ctx.workflow.next_step.clone(),
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        blocker_metadata,
    }
}

fn retention_execution_target(
    candidate: &RetentionDryRunCandidate,
    requested_policy: &RetentionExecutionRequestedPolicy,
    reason_code: &str,
) -> RetentionExecutionTargetEvidence {
    let policy_action = requested_policy
        .disposal_action
        .map(RetentionDisposalAction::as_str)
        .unwrap_or("unknown_policy_action");
    RetentionExecutionTargetEvidence {
        target_type: "retention_candidate_record".to_owned(),
        target_id: candidate.record_id.clone().unwrap_or_else(|| {
            format!(
                "scope:{};category:{}",
                candidate.scope.as_str(),
                candidate.category.as_str()
            )
        }),
        action: format!("bounded_{policy_action}_evidence"),
        reason_code: reason_code.to_owned(),
        detail: match requested_policy.id.as_deref() {
            Some(policy_id) => format!(
                "candidate scope={} category={} evaluated against policy {}; bounded evidence only",
                candidate.scope, candidate.category, policy_id
            ),
            None => format!(
                "candidate scope={} category={} evaluated without a registered policy; no disposal executed",
                candidate.scope, candidate.category
            ),
        },
    }
}

fn outcome_reason_code(outcome: RetentionExecutionOutcome) -> &'static str {
    match outcome {
        RetentionExecutionOutcome::BlockedMissingPolicy => "requested_policy_required",
        RetentionExecutionOutcome::BlockedStalePolicy => "requested_policy_active",
        RetentionExecutionOutcome::BlockedPolicyMismatch => "requested_policy_scope_match",
        RetentionExecutionOutcome::BlockedLegalHold => "legal_hold_release",
        RetentionExecutionOutcome::BlockedDestructiveAction => "destructive_action_disabled",
        RetentionExecutionOutcome::BlockedApprovalMismatch => "execution_approval_match",
        RetentionExecutionOutcome::BlockedMissingTarget => "candidate_record_required",
        RetentionExecutionOutcome::ManualReviewRequired => "retention_manual_review",
        RetentionExecutionOutcome::BoundedArchiveRecorded => "bounded_archive_recorded",
        RetentionExecutionOutcome::BoundedNoActionRecorded => "bounded_no_action_recorded",
        RetentionExecutionOutcome::AlreadyExecuted => "already_executed",
    }
}

fn retention_execution_evidence_state(
    outcome: RetentionExecutionOutcome,
) -> RetentionEvidenceState {
    match outcome {
        RetentionExecutionOutcome::ManualReviewRequired => RetentionEvidenceState::ReviewQueued,
        RetentionExecutionOutcome::BoundedArchiveRecorded => {
            RetentionEvidenceState::BoundedArchiveRecorded
        }
        RetentionExecutionOutcome::BoundedNoActionRecorded => {
            RetentionEvidenceState::BoundedNoActionRecorded
        }
        RetentionExecutionOutcome::AlreadyExecuted => {
            RetentionEvidenceState::PriorBoundedEvidenceAvailable
        }
        RetentionExecutionOutcome::BlockedMissingPolicy
        | RetentionExecutionOutcome::BlockedStalePolicy
        | RetentionExecutionOutcome::BlockedPolicyMismatch
        | RetentionExecutionOutcome::BlockedLegalHold
        | RetentionExecutionOutcome::BlockedDestructiveAction
        | RetentionExecutionOutcome::BlockedApprovalMismatch
        | RetentionExecutionOutcome::BlockedMissingTarget => RetentionEvidenceState::Blocked,
    }
}

fn retention_execution_evidence_next_step(
    outcome: RetentionExecutionOutcome,
    workflow_next_step: &str,
) -> String {
    match outcome {
        RetentionExecutionOutcome::BoundedArchiveRecorded => {
            "Bounded archive evidence recorded; no destructive operation was performed.".to_owned()
        }
        RetentionExecutionOutcome::BoundedNoActionRecorded => {
            "Bounded no-action evidence recorded; no destructive operation was performed.".to_owned()
        }
        RetentionExecutionOutcome::AlreadyExecuted => {
            "Prior bounded evidence is already available for this target/policy; no duplicate action was recorded.".to_owned()
        }
        _ => workflow_next_step.to_owned(),
    }
}

fn apply_execution_result_to_matches(
    record: &RetentionExecutionRecord,
    matches: &mut [RetentionDryRunMatch],
) {
    if !matches!(
        record.outcome,
        RetentionExecutionOutcome::BoundedArchiveRecorded
            | RetentionExecutionOutcome::BoundedNoActionRecorded
    ) {
        return;
    }
    let Some(policy_id) = record.requested_policy.id.as_deref() else {
        return;
    };
    for matched in matches {
        if matched.policy_id == policy_id {
            matched.would_execute = true;
            matched.reason = "bounded retention execution evidence recorded";
        }
    }
}

fn retention_execution_status(outcome: RetentionExecutionOutcome) -> RetentionExecutionStatus {
    match outcome {
        RetentionExecutionOutcome::ManualReviewRequired => RetentionExecutionStatus::AwaitingReview,
        RetentionExecutionOutcome::BoundedArchiveRecorded
        | RetentionExecutionOutcome::BoundedNoActionRecorded
        | RetentionExecutionOutcome::AlreadyExecuted => RetentionExecutionStatus::Executed,
        RetentionExecutionOutcome::BlockedMissingPolicy
        | RetentionExecutionOutcome::BlockedStalePolicy
        | RetentionExecutionOutcome::BlockedPolicyMismatch
        | RetentionExecutionOutcome::BlockedLegalHold
        | RetentionExecutionOutcome::BlockedDestructiveAction
        | RetentionExecutionOutcome::BlockedApprovalMismatch
        | RetentionExecutionOutcome::BlockedMissingTarget => RetentionExecutionStatus::Blocked,
    }
}

fn parse_retention_execution_status_filter(
    raw: Option<String>,
) -> Result<Option<RetentionExecutionStatus>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match normalize_enum(&raw).as_str() {
        "" | "all" => Ok(None),
        "awaiting" | "awaiting_review" => Ok(Some(RetentionExecutionStatus::AwaitingReview)),
        "blocked" => Ok(Some(RetentionExecutionStatus::Blocked)),
        "executed" => Ok(Some(RetentionExecutionStatus::Executed)),
        _ => Err(ApiError::Unprocessable(
            "invalid retention execution status filter; expected blocked, awaiting_review, executed, or all"
                .to_owned(),
        )),
    }
}

fn retention_operator_review_decision(
    outcome: RetentionExecutionOutcome,
) -> RetentionOperatorReviewDecision {
    match outcome {
        RetentionExecutionOutcome::ManualReviewRequired => {
            RetentionOperatorReviewDecision::ReviewRequired
        }
        RetentionExecutionOutcome::BoundedArchiveRecorded
        | RetentionExecutionOutcome::BoundedNoActionRecorded
        | RetentionExecutionOutcome::AlreadyExecuted => {
            RetentionOperatorReviewDecision::ExecutionRecorded
        }
        RetentionExecutionOutcome::BlockedMissingPolicy
        | RetentionExecutionOutcome::BlockedStalePolicy
        | RetentionExecutionOutcome::BlockedPolicyMismatch
        | RetentionExecutionOutcome::BlockedLegalHold
        | RetentionExecutionOutcome::BlockedDestructiveAction
        | RetentionExecutionOutcome::BlockedApprovalMismatch
        | RetentionExecutionOutcome::BlockedMissingTarget => {
            RetentionOperatorReviewDecision::Blocked
        }
    }
}

fn normalize_retention_execution_record(record: &mut RetentionExecutionRecord) {
    record.execution_status = retention_execution_status(record.outcome);
    record.operator_review_decision = retention_operator_review_decision(record.outcome);
    record.evidence_state = retention_execution_evidence_state(record.outcome);
    record.evidence_next_step =
        retention_execution_evidence_next_step(record.outcome, &record.workflow.next_step);
    record.destructive_disposal_completed = false;
    record.full_erasure_completed = false;
    record.legal_hold_mutated = false;
    record.retention_policy_mutated = false;
}

fn default_retention_execution_intent() -> RetentionExecutionIntent {
    RetentionExecutionIntent::ReviewOnly
}

fn default_retention_execution_status() -> RetentionExecutionStatus {
    RetentionExecutionStatus::AwaitingReview
}

fn default_retention_operator_review_decision() -> RetentionOperatorReviewDecision {
    RetentionOperatorReviewDecision::ReviewRequired
}

fn default_retention_execution_decision_state() -> RetentionExecutionDecisionState {
    RetentionExecutionDecisionState::Open
}

fn default_retention_evidence_state() -> RetentionEvidenceState {
    RetentionEvidenceState::ReviewQueued
}

fn legacy_retention_operator_workflow() -> RetentionOperatorWorkflow {
    RetentionOperatorWorkflow {
        status: RetentionOperatorWorkflowStatus::AwaitingManualReview,
        blockers: Vec::new(),
        required_approvals: vec![retention_required_approval(
            "retention_manual_review",
            "privacy_or_settings_manager",
            "approve the retained evidence before any separate operational action",
        )],
        next_step: "Review the retained execution evidence; no disposal has been executed."
            .to_owned(),
    }
}

fn legacy_retention_execution_result() -> RetentionExecutionResult {
    RetentionExecutionResult {
        bounded_executor: true,
        executed_at: None,
        executed_by: None,
        targets_considered: Vec::new(),
        targets_acted: Vec::new(),
        targets_skipped: Vec::new(),
        reason_codes: vec!["legacy_review_only_record".to_owned()],
        next_step: "Review the retained execution evidence; no disposal has been executed."
            .to_owned(),
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        blocker_metadata: Vec::new(),
    }
}

fn retention_policy_id(raw: Option<String>) -> Result<RetentionPolicyId, ApiError> {
    let Some(raw) = raw else {
        return Ok(RetentionPolicyId(Uuid::new_v4()));
    };
    parse_retention_policy_id(raw, "id")
}

fn parse_retention_policy_id(raw: String, field: &str) -> Result<RetentionPolicyId, ApiError> {
    let value = required_retention_segment(Some(raw), field, MAX_RETENTION_FIELD_CHARS)?;
    Uuid::parse_str(&value)
        .map(RetentionPolicyId)
        .map_err(|_| ApiError::Unprocessable(format!("{field} must be a valid UUID")))
}

fn retention_record_reference(raw: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = clean_optional_bounded(raw, "record_id", MAX_RETENTION_FIELD_CHARS)? else {
        return Ok(None);
    };
    reject_path_like_value(&value, "record_id")?;
    Ok(Some(value))
}

fn required_retention_segment(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<String, ApiError> {
    let value = required_bounded_string(raw, field, max_chars)?;
    reject_path_like_value(&value, field)?;
    Ok(value)
}

fn required_privacy_control_segment(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<String, ApiError> {
    let value = required_bounded_string(raw, field, max_chars)?;
    reject_path_like_value(&value, field)?;
    Ok(value)
}

fn required_sensitive_checked_text(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<String, ApiError> {
    let value = required_string(raw, field)?;
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    reject_sensitive_evidence_markers(&value, field)?;
    Ok(value)
}

fn optional_rfc3339_string(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = clean_optional_bounded(raw, field, max_chars)? else {
        return Ok(None);
    };
    OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| ApiError::Unprocessable(format!("{field} must be an RFC 3339 timestamp")))?;
    Ok(Some(value))
}

fn optional_sensitive_checked_text(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    clean_optional_bounded(raw, field, max_chars)
}

fn validate_dpia_evidence_receipt(
    raw: DpiaEvidenceReceiptInput,
    actor_name: &str,
) -> Result<DpiaEvidenceReceipt, ApiError> {
    reject_true_flag(
        raw.authority_filing_completed,
        "evidence_receipt.authority_filing_completed",
        "authority filing",
    )?;
    reject_true_flag(
        raw.legal_review_accepted,
        "evidence_receipt.legal_review_accepted",
        "legal acceptance",
    )?;
    reject_true_flag(
        raw.legal_certification_completed,
        "evidence_receipt.legal_certification_completed",
        "legal certification",
    )?;
    reject_true_flag(
        raw.external_delivery_completed,
        "evidence_receipt.external_delivery_completed",
        "external delivery",
    )?;
    reject_true_flag(
        raw.dpia_completed,
        "evidence_receipt.dpia_completed",
        "DPIA completion",
    )?;
    reject_true_flag(
        raw.compliance_certification_completed,
        "evidence_receipt.compliance_certification_completed",
        "compliance certification",
    )?;
    let evidence_type = raw
        .evidence_type
        .as_deref()
        .map(DpiaEvidenceKind::parse)
        .transpose()?
        .unwrap_or(DpiaEvidenceKind::Review);
    Ok(DpiaEvidenceReceipt {
        id: Uuid::new_v4().to_string(),
        evidence_type,
        recorded_at: now_rfc3339(),
        recorded_by: actor_name.to_owned(),
        occurred_at: optional_rfc3339_string(
            raw.occurred_at,
            "evidence_receipt.occurred_at",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        notes: optional_sensitive_checked_text(
            raw.notes,
            "evidence_receipt.notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        authority_filing_completed: false,
        legal_review_accepted: false,
        legal_certification_completed: false,
        external_delivery_completed: false,
        dpia_completed: false,
        compliance_certification_completed: false,
    })
}

fn validate_breach_evidence_receipt(
    raw: BreachEvidenceReceiptInput,
    actor_name: &str,
) -> Result<BreachPlaybookEvidenceReceipt, ApiError> {
    reject_true_flag(
        raw.authority_notified,
        "evidence_receipt.authority_notified",
        "authority notification",
    )?;
    reject_true_flag(
        raw.subjects_notified,
        "evidence_receipt.subjects_notified",
        "data-subject notification",
    )?;
    reject_true_flag(
        raw.notification_completed,
        "evidence_receipt.notification_completed",
        "notification completion",
    )?;
    reject_true_flag(
        raw.incident_closed,
        "evidence_receipt.incident_closed",
        "incident completion",
    )?;
    let evidence_type = raw
        .evidence_type
        .as_deref()
        .map(BreachEvidenceKind::parse)
        .transpose()?
        .unwrap_or(BreachEvidenceKind::Review);
    Ok(BreachPlaybookEvidenceReceipt {
        id: Uuid::new_v4().to_string(),
        evidence_type,
        recorded_at: now_rfc3339(),
        recorded_by: actor_name.to_owned(),
        occurred_at: optional_rfc3339_string(
            raw.occurred_at,
            "evidence_receipt.occurred_at",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        notes: optional_sensitive_checked_text(
            raw.notes,
            "evidence_receipt.notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        authority_notified: false,
        subjects_notified: false,
    })
}

fn validate_transfer_evidence_receipt(
    raw: TransferEvidenceReceiptInput,
    actor_name: &str,
) -> Result<TransferControlEvidenceReceipt, ApiError> {
    reject_true_flag(
        raw.transfer_approved,
        "evidence_receipt.transfer_approved",
        "transfer approval",
    )?;
    reject_true_flag(
        raw.data_transfer_executed,
        "evidence_receipt.data_transfer_executed",
        "data-transfer execution",
    )?;
    reject_true_flag(
        raw.legal_certification_completed,
        "evidence_receipt.legal_certification_completed",
        "legal certification",
    )?;
    Ok(TransferControlEvidenceReceipt {
        id: Uuid::new_v4().to_string(),
        recorded_at: now_rfc3339(),
        recorded_by: actor_name.to_owned(),
        reviewed_at: optional_rfc3339_string(
            raw.reviewed_at,
            "evidence_receipt.reviewed_at",
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?,
        notes: optional_sensitive_checked_text(
            raw.notes,
            "evidence_receipt.notes",
            MAX_PRIVACY_CONTROL_TEXT_CHARS,
        )?,
        transfer_approved: false,
        data_transfer_executed: false,
    })
}

fn reject_true_flag(value: Option<bool>, field: &str, action: &str) -> Result<(), ApiError> {
    if value == Some(true) {
        Err(ApiError::Unprocessable(format!(
            "{field} cannot be true; this API records review evidence only and does not perform {action}"
        )))
    } else {
        Ok(())
    }
}

fn reject_retention_review_closure_claims(value: &str, field: &str) -> Result<(), ApiError> {
    const CLAIM_TERMS: &[&str] = &[
        "legal approval",
        "legal approved",
        "legally approved",
        "approved by legal",
        "disposed",
        "deleted",
        "deletion",
        "erased",
        "erasure",
        "resolved",
    ];
    let normalized = value.to_ascii_lowercase();
    if let Some(term) = CLAIM_TERMS.iter().find(|term| normalized.contains(**term)) {
        Err(ApiError::Unprocessable(format!(
            "{field} cannot claim {term}; review closure records bounded evidence only"
        )))
    } else {
        Ok(())
    }
}

fn reject_retention_candidate_resolution_claims(value: &str, field: &str) -> Result<(), ApiError> {
    const CLAIM_FAMILIES: &[(&str, &[&str])] = &[
        (
            "deletion",
            &[
                "deleted",
                "deletion",
                "delete completed",
                "delete complete",
                "delete performed",
                "records deleted",
                "record deleted",
            ],
        ),
        (
            "anonymization",
            &[
                "anonymized",
                "anonymised",
                "anonymization",
                "anonymisation",
                "records anonymized",
                "records anonymised",
            ],
        ),
        (
            "redaction",
            &[
                "redacted",
                "redaction",
                "document redacted",
                "documents redacted",
                "record redacted",
                "records redacted",
            ],
        ),
        (
            "GDPR erasure",
            &[
                "gdpr erasure",
                "gdpr erased",
                "gdpr erase",
                "full erasure",
                "erased",
                "erasure",
                "erasure completed",
                "erasure complete",
                "erasure performed",
            ],
        ),
        (
            "legal hold mutation",
            &[
                "legal hold mutation",
                "legal hold mutated",
                "legal hold change",
                "legal hold changed",
                "legal hold update",
                "legal hold updated",
                "legal hold release",
                "legal hold released",
                "legal hold resolution",
                "legal hold resolved",
                "legal hold removal",
                "legal hold removed",
                "legal hold lift",
                "legal hold lifted",
                "hold mutation recorded",
            ],
        ),
        (
            "retention policy mutation",
            &[
                "retention policy mutation",
                "retention policy mutated",
                "retention policy change",
                "retention policy changed",
                "retention policy update",
                "retention policy updated",
                "retention policy amendment",
                "retention policy amended",
                "policy mutation",
                "policy mutation recorded",
                "policy changed",
                "policy updated",
            ],
        ),
        (
            "legal disposal",
            &[
                "legal disposal",
                "legally disposed",
                "disposed",
                "disposal completion",
                "disposal completed",
                "disposal complete",
                "disposal performed",
                "disposal approval",
                "disposal approved",
                "disposal resolution",
                "disposal resolved",
            ],
        ),
        (
            "legal completion",
            &[
                "legal completion",
                "legally completed",
                "legal completed",
                "completion approved by legal",
                "completed by legal",
            ],
        ),
        (
            "legal approval",
            &[
                "legal approval",
                "legal approved",
                "legally approved",
                "approved by legal",
            ],
        ),
        (
            "legal resolution",
            &[
                "legal resolution",
                "legally resolved",
                "legal resolved",
                "resolved by legal",
            ],
        ),
    ];
    let normalized = value.to_ascii_lowercase();
    for (family, terms) in CLAIM_FAMILIES {
        if terms.iter().any(|term| normalized.contains(*term)) {
            return Err(ApiError::Unprocessable(format!(
                "{field} cannot claim {family}; candidate resolution records evidence only"
            )));
        }
    }
    Ok(())
}

fn reject_path_like_value(value: &str, field: &str) -> Result<(), ApiError> {
    let lower = value.to_ascii_lowercase();
    let looks_like_path = value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || lower.contains("..")
        || lower.starts_with('~')
        || value == "."
        || value == ".."
        || (value.len() >= 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic());
    if looks_like_path {
        Err(ApiError::Unprocessable(format!(
            "{field} must not contain path-like values"
        )))
    } else {
        Ok(())
    }
}

fn retention_policy_applies(record: &RetentionPolicyRecord, scope: &str, category: &str) -> bool {
    record.active
        && record.status == RetentionPolicyStatus::Active
        && retention_value_matches(&record.scope, scope)
        && retention_value_matches(&record.category, category)
}

fn retention_value_matches(policy_value: &str, target: &str) -> bool {
    let policy_value = policy_value.trim();
    policy_value.eq_ignore_ascii_case(target) || policy_value.eq_ignore_ascii_case("all")
}

fn required_string(raw: Option<String>, field: &str) -> Result<String, ApiError> {
    raw.ok_or_else(|| ApiError::Unprocessable(format!("{field} is required")))
        .and_then(|value| clean_required(&value, field))
}

fn validate_dsr_execution(
    input: DsrExecutionInput,
    request_type: DsrRequestType,
) -> Result<ValidatedDsrExecution, ApiError> {
    let outcome = input
        .outcome
        .as_deref()
        .map(DsrExecutionOutcome::parse)
        .transpose()?
        .unwrap_or(match request_type {
            DsrRequestType::Erasure => DsrExecutionOutcome::PartiallyFulfilled,
            DsrRequestType::Export
            | DsrRequestType::Rectification
            | DsrRequestType::Restriction => DsrExecutionOutcome::Fulfilled,
        });
    let execution_notes = clean_optional_bounded(
        input.execution_notes,
        "execution_notes",
        MAX_DSR_EXECUTION_NOTE_CHARS,
    )?;
    let affected_records = sanitize_affected_records(input.affected_records)?;
    let retention_review = clean_optional_bounded(
        input.retention_review,
        "retention_review",
        MAX_DSR_REVIEW_CHARS,
    )?;
    let legal_basis_review = clean_optional_bounded(
        input.legal_basis_review,
        "legal_basis_review",
        MAX_DSR_REVIEW_CHARS,
    )?;
    let erasure_plan = sanitize_dsr_erasure_plan(input.erasure_plan)?;
    if request_type != DsrRequestType::Erasure && erasure_plan.is_some() {
        return Err(ApiError::Unprocessable(
            "erasure_plan is only allowed for erasure DSR requests".to_owned(),
        ));
    }
    if request_type == DsrRequestType::Erasure && outcome == DsrExecutionOutcome::Fulfilled {
        return Err(ApiError::Unprocessable(
            "erasure DSR requests cannot be marked fulfilled because immutable ledger/audit records are retained; use partially_fulfilled, rejected, or no_action_required"
                .to_owned(),
        ));
    }
    Ok(ValidatedDsrExecution {
        completion_reason: clean_optional(input.completion_reason),
        outcome,
        execution_notes,
        affected_records,
        retention_review,
        legal_basis_review,
        erasure_plan,
    })
}

fn sanitize_affected_records(
    raw: Option<Vec<DsrAffectedRecordInput>>,
) -> Result<Vec<DsrAffectedRecordSummary>, ApiError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_DSR_AFFECTED_RECORDS {
        return Err(ApiError::Unprocessable(format!(
            "affected_records must include at most {MAX_DSR_AFFECTED_RECORDS} entries"
        )));
    }

    raw.into_iter()
        .map(|record| {
            let collection = required_bounded_string(
                record.collection,
                "affected_records.collection",
                MAX_DSR_AFFECTED_FIELD_CHARS,
            )?;
            let action = required_bounded_string(
                record.action,
                "affected_records.action",
                MAX_DSR_AFFECTED_FIELD_CHARS,
            )?;
            let count = record.count.ok_or_else(|| {
                ApiError::Unprocessable("affected_records.count is required".to_owned())
            })?;
            if count > MAX_DSR_AFFECTED_RECORD_COUNT {
                return Err(ApiError::Unprocessable(format!(
                    "affected_records.count must be at most {MAX_DSR_AFFECTED_RECORD_COUNT}"
                )));
            }
            Ok(DsrAffectedRecordSummary {
                collection,
                action,
                count,
            })
        })
        .collect()
}

fn sanitize_dsr_erasure_plan(
    raw: Option<Vec<DsrMutableSidecarPlanInput>>,
) -> Result<Option<Vec<DsrMutableSidecarPlan>>, ApiError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > MAX_DSR_ERASURE_PLAN_ITEMS {
        return Err(ApiError::Unprocessable(format!(
            "erasure_plan must include at most {MAX_DSR_ERASURE_PLAN_ITEMS} entries"
        )));
    }

    raw.into_iter()
        .map(|item| {
            let collection = required_privacy_control_segment(
                item.collection,
                "erasure_plan.collection",
                MAX_DSR_AFFECTED_FIELD_CHARS,
            )?;
            let record_id = clean_optional_bounded(
                item.record_id,
                "erasure_plan.record_id",
                MAX_DSR_AFFECTED_FIELD_CHARS,
            )?;
            if let Some(record_id) = record_id.as_deref() {
                reject_path_like_value(record_id, "erasure_plan.record_id")?;
            }
            let action = item
                .action
                .as_deref()
                .ok_or_else(|| {
                    ApiError::Unprocessable("erasure_plan.action is required".to_owned())
                })
                .and_then(DsrMutableSidecarAction::parse)?;
            let status = item
                .status
                .as_deref()
                .map(DsrMutableSidecarPlanStatus::parse)
                .transpose()?
                .unwrap_or(DsrMutableSidecarPlanStatus::ManualReviewRequired);
            let reason = optional_sensitive_checked_text(
                item.reason,
                "erasure_plan.reason",
                MAX_DSR_REVIEW_CHARS,
            )?;
            Ok(DsrMutableSidecarPlan {
                collection,
                record_id,
                action,
                status,
                reason,
                mutation_completed: false,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

async fn build_dsr_erasure_preflight(
    state: &AppState,
    request: &DsrRequest,
    actor_name: &str,
    assessed_at: &str,
    provided_plan: Vec<DsrMutableSidecarPlan>,
) -> DsrErasurePreflight {
    let ledger_event_count = dsr_subject_ledger_event_count(state, request.subject_user_id).await;
    let mutable_sidecar_plan = dsr_erasure_sidecar_plan(request, provided_plan);

    DsrErasurePreflight {
        dsr_request_id: request.id.to_string(),
        subject_user_id: request.subject_user_id.to_string(),
        assessed_at: assessed_at.to_owned(),
        assessed_by: actor_name.to_owned(),
        status: DsrErasurePreflightStatus::BlockedImmutableLedger,
        ledger_event_count_before_completion: ledger_event_count,
        immutable_ledger_blockers: vec![
            DsrErasureBlocker {
                code: "immutable_ledger_events".to_owned(),
                target: format!("user:{}", request.subject_user_id),
                detail: format!(
                    "{ledger_event_count} existing ledger event reference(s) matched before completion; ledger entries are append-only accountability records and are not erased by this API"
                ),
            },
            DsrErasureBlocker {
                code: "dsr_audit_chain_retention".to_owned(),
                target: format!("privacy:dsr-request:{}", request.id),
                detail:
                    "DSR create/complete audit events and attestations are retained; completion records preflight evidence only"
                        .to_owned(),
            },
        ],
        mutable_sidecar_plan,
        idempotency_guard: DsrErasureIdempotencyGuard {
            request_id: request.id.to_string(),
            state_transition: "pending_to_completed_once".to_owned(),
            duplicate_completion_behavior: "conflict_existing_completed_request".to_owned(),
            ledger_event_kind: DSR_COMPLETED_KIND.to_owned(),
        },
        destructive_mutation_completed: false,
        full_erasure_completed: false,
    }
}

async fn dsr_subject_ledger_event_count(state: &AppState, subject_user_id: UserId) -> usize {
    let subject_id = subject_user_id.to_string();
    let user_scope = format!("user:{subject_id}");
    let username = {
        let users = state.users.read().await;
        users
            .get(&subject_user_id)
            .map(|user| user.username.clone())
    };
    let ledger = state.ledger.read().await;
    ledger
        .events()
        .iter()
        .filter(|event| {
            event.scope == user_scope
                || event.actor == subject_id
                || username
                    .as_deref()
                    .is_some_and(|username| event.actor == username)
        })
        .count()
}

fn dsr_erasure_sidecar_plan(
    request: &DsrRequest,
    mut provided_plan: Vec<DsrMutableSidecarPlan>,
) -> Vec<DsrMutableSidecarPlan> {
    if provided_plan.is_empty() {
        provided_plan.push(DsrMutableSidecarPlan {
            collection: "users".to_owned(),
            record_id: Some(request.subject_user_id.to_string()),
            action: DsrMutableSidecarAction::Review,
            status: DsrMutableSidecarPlanStatus::ManualReviewRequired,
            reason: Some(
                "Mutable user sidecar review is required before any separate redaction or anonymization workflow"
                    .to_owned(),
            ),
            mutation_completed: false,
        });
    }

    let dsr_record_id = request.id.to_string();
    let has_dsr_marker = provided_plan.iter().any(|item| {
        item.collection == DSR_REQUESTS_FILE
            && item.record_id.as_deref() == Some(dsr_record_id.as_str())
    });
    if !has_dsr_marker {
        provided_plan.push(DsrMutableSidecarPlan {
            collection: DSR_REQUESTS_FILE.to_owned(),
            record_id: Some(dsr_record_id),
            action: DsrMutableSidecarAction::Retain,
            status: DsrMutableSidecarPlanStatus::NotApplicable,
            reason: Some(
                "The DSR request sidecar is retained as accountability evidence; no erasure mutation was executed"
                    .to_owned(),
            ),
            mutation_completed: false,
        });
    }
    provided_plan
}

// =================================================================================================
// wp26-gdpr: destructive right-to-erasure workflow (preflight → approve → execute → attest)
//
// Turns the evidence-only erasure preflight into a real, dual-control-gated destructive workflow that
// PRESERVES ledger integrity. The append-only ledger is NEVER mutated: erasure physically deletes the
// subject's live directory identity (the `users` row — username / display_name / email) and
// crypto-erases the subject's per-subject DEK (destroying the wrapped DEK makes any DEK-encrypted
// subject PII — live rows AND backups — cryptographically irrecoverable), then appends exactly one
// `subject.erased` attestation event, so `Ledger::verify()` advances Ok(n) → Ok(n+1). Lawfully
// retained Art. 17(3) carve-outs (ledger events, DSR audit trail, sealed acts/books/signed documents)
// are surfaced, never silently skipped. Destructive steps are NOT reachable via API key / MCP.
// =================================================================================================

const ERASE_TECHNIQUE_PHYSICAL: &str = "physical_delete";
const ERASE_TECHNIQUE_CRYPTO: &str = "crypto_erase";
const ERASE_TECHNIQUE_VACUUM: &str = "vacuum";

/// One concrete erasable target enumerated by the destructive-erasure preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasableTarget {
    pub collection: String,
    pub id: String,
    /// `physical_delete` (row/sidecar removal + VACUUM) or `crypto_erase` (destroy the subject DEK).
    pub technique: String,
    pub count: u64,
}

/// One lawfully-retained carve-out (GDPR Art. 17(3)) surfaced by the preflight, with its legal basis
/// and the remedy the data subject is entitled to instead of erasure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedCarveout {
    pub collection: String,
    pub legal_basis: String,
    pub detail: String,
    /// The data-subject remedy for this retained record: `annotation` (record an append-only
    /// rectification / restriction note against it — the standard remedy for sealed acts / books /
    /// signed documents whose signatures must stay valid) or `retained_no_action`.
    pub remedy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureWorkflowStatus {
    /// Erasable targets exist and no blocking hold applies — the plan may be approved and executed.
    ReadyForApproval,
    /// A legal hold blocks erasure of the subject's records.
    BlockedLegalHold,
    /// Nothing erasable remains for this subject (already erased, or never present).
    NothingToErase,
}

/// The concrete, digest-bound erasure plan the preflight returns. Evidence only; nothing is destroyed
/// until an approved execute runs against a matching digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErasurePreflightReport {
    pub dsr_request_id: String,
    pub subject_user_id: String,
    pub assessed_at: String,
    pub assessed_by: String,
    pub status: ErasureWorkflowStatus,
    pub erasable_targets: Vec<ErasableTarget>,
    pub retained_carveouts: Vec<RetainedCarveout>,
    pub ledger_event_count_matched: usize,
    pub subject_dek_present: bool,
    /// sha256 (lowercase hex) over the canonical erasable plan (subject + sorted targets + DEK flag).
    /// Approval and execution bind to this digest so the store cannot change between plan and
    /// destruction without the mismatch being rejected (anti-TOCTOU).
    pub preflight_digest: String,
}

/// Dual-control authorization recorded on the DSR record once a distinct approver approves the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureAuthorization {
    pub preflight_digest: String,
    pub requested_by: String,
    pub approved_by: String,
    pub approved_at: String,
    pub carveouts_acknowledged: bool,
}

/// The attestation record written onto the DSR record once the destructive execute commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureExecutionRecord {
    pub executed_by: String,
    pub executed_at: String,
    pub subject_erased_event_id: String,
    pub techniques: Vec<String>,
    pub erased_targets: Vec<DsrAffectedRecordSummary>,
    pub retained_carveouts: Vec<RetainedCarveout>,
    pub dek_destroyed: bool,
    pub vacuum_completed: bool,
    pub pre_erasure_ledger_head: usize,
    pub ledger_event_count_matched: usize,
}

#[derive(Deserialize)]
pub struct ApproveErasureBody {
    /// The preflight digest the approver reviewed; must match a fresh recompute (anti-TOCTOU).
    #[serde(default)]
    pub preflight_digest: String,
    /// Typed confirmation echoing the subject user id (guards against approving the wrong subject).
    #[serde(default)]
    pub subject_confirmation: String,
    /// Explicit acknowledgement of the retained Art. 17(3) carve-outs.
    #[serde(default)]
    pub acknowledge_carveouts: bool,
}

#[derive(Deserialize)]
pub struct ExecuteErasureBody {
    /// Must equal the approved authorization digest AND a fresh recompute at execution time.
    #[serde(default)]
    pub preflight_digest: String,
}

struct ErasurePlanEnumeration {
    erasable_targets: Vec<ErasableTarget>,
    retained_carveouts: Vec<RetainedCarveout>,
    subject_dek_present: bool,
    ledger_event_count: usize,
    legal_hold_blocked: bool,
}

/// Destructive erasure is gated to interactive sessions with `user.manage@Global`; it is deliberately
/// NOT reachable via an API key / MCP principal (destructive step-up operations stay off that path).
fn reject_api_key_for_destructive(actor: &CurrentActor) -> Result<(), ApiError> {
    if actor.is_api_key() {
        return Err(forbidden());
    }
    Ok(())
}

/// Load an erasure DSR request, checking the subject matches and the request is an erasure request.
async fn load_erasure_request(
    state: &AppState,
    request_id: DsrRequestId,
    subject: UserId,
) -> Result<DsrRequest, ApiError> {
    let requests = state.dsr_requests.read().await;
    let request = requests
        .get(&request_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if request.subject_user_id != subject {
        return Err(ApiError::NotFound);
    }
    if request.request_type != DsrRequestType::Erasure {
        return Err(ApiError::Unprocessable(
            "DSR request is not an erasure request".to_owned(),
        ));
    }
    Ok(request)
}

/// Enumerate the subject's concrete erasable targets and the retained Art. 17(3) carve-outs. Reads
/// only; never mutates. The `users` row is the primary erasable PII (username / display_name /
/// email); the subject DEK is crypto-erasable. Delegations naming the subject are surfaced as a
/// retained manual-review carve-out rather than auto-deleted.
async fn enumerate_erasure_plan(state: &AppState, request: &DsrRequest) -> ErasurePlanEnumeration {
    let subject = request.subject_user_id;
    let subject_id = subject.to_string();
    let subject_present = state.users.read().await.contains_key(&subject);
    let subject_dek_present = match &state.store {
        Some(store) => {
            let subject_id = subject_id.clone();
            store
                .read_blocking_async(move |s| s.get_subject_key(&subject_id))
                .await
                .ok()
                .flatten()
                .map(|row| row.erased_at.is_none() && !row.wrapped_dek.is_empty())
                .unwrap_or(false)
        }
        None => false,
    };
    let ledger_event_count = dsr_subject_ledger_event_count(state, subject).await;

    let mut erasable_targets = Vec::new();
    if subject_present {
        erasable_targets.push(ErasableTarget {
            collection: "users".to_owned(),
            id: subject_id.clone(),
            technique: ERASE_TECHNIQUE_PHYSICAL.to_owned(),
            count: 1,
        });
    }
    if subject_dek_present {
        erasable_targets.push(ErasableTarget {
            collection: "subject_keys".to_owned(),
            id: subject_id.clone(),
            technique: ERASE_TECHNIQUE_CRYPTO.to_owned(),
            count: 1,
        });
    }

    let retained_carveouts = vec![
        RetainedCarveout {
            collection: "ledger_events".to_owned(),
            legal_basis: "art_17_3_legal_claims_and_tamper_evidence".to_owned(),
            detail: format!(
                "{ledger_event_count} append-only ledger event(s) reference the subject; retained as accountability + tamper-evidence records and never rewritten"
            ),
            remedy: "retained_no_action".to_owned(),
        },
        RetainedCarveout {
            collection: DSR_REQUESTS_FILE.to_owned(),
            legal_basis: "art_5_2_accountability".to_owned(),
            detail:
                "the DSR request audit trail and the subject.erased attestation are retained as proof the erasure occurred"
                    .to_owned(),
            remedy: "retained_no_action".to_owned(),
        },
        RetainedCarveout {
            collection: "acts_books_signed_documents".to_owned(),
            legal_basis: "art_17_3_b_statutory_retention".to_owned(),
            detail:
                "sealed minutes (acts), books + termo de abertura, and signed legal documents carry a statutory retention obligation and their signatures must stay valid; the subject's remedy is an append-only rectification / restriction annotation, NOT erasure"
                    .to_owned(),
            remedy: "annotation".to_owned(),
        },
        RetainedCarveout {
            collection: "delegations".to_owned(),
            legal_basis: "art_17_3_manual_review".to_owned(),
            detail:
                "role delegations naming the subject are retained pending a separate accountability review; not auto-deleted by this workflow"
                    .to_owned(),
            remedy: "retained_no_action".to_owned(),
        },
    ];

    ErasurePlanEnumeration {
        erasable_targets,
        retained_carveouts,
        subject_dek_present,
        ledger_event_count,
        legal_hold_blocked: false,
    }
}

/// Canonical, order-independent sha256 (lowercase hex) over the erasable plan. Binds approval +
/// execution to the exact set of targets so a store change between plan and destruction is rejected.
fn compute_preflight_digest(
    subject_user_id: &UserId,
    targets: &[ErasableTarget],
    dek_present: bool,
) -> String {
    let mut sorted = targets.to_vec();
    sorted.sort_by(|a, b| {
        (a.collection.as_str(), a.id.as_str(), a.technique.as_str()).cmp(&(
            b.collection.as_str(),
            b.id.as_str(),
            b.technique.as_str(),
        ))
    });
    let canonical = serde_json::json!({
        "subject_user_id": subject_user_id.to_string(),
        "subject_dek_present": dek_present,
        "targets": sorted,
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn build_erasure_preflight_report(
    state: &AppState,
    request: &DsrRequest,
    assessed_by: &str,
) -> ErasurePreflightReport {
    let assessed_at = now_rfc3339();
    let enumeration = enumerate_erasure_plan(state, request).await;
    let status = if enumeration.legal_hold_blocked {
        ErasureWorkflowStatus::BlockedLegalHold
    } else if enumeration.erasable_targets.is_empty() {
        ErasureWorkflowStatus::NothingToErase
    } else {
        ErasureWorkflowStatus::ReadyForApproval
    };
    let preflight_digest = compute_preflight_digest(
        &request.subject_user_id,
        &enumeration.erasable_targets,
        enumeration.subject_dek_present,
    );
    ErasurePreflightReport {
        dsr_request_id: request.id.to_string(),
        subject_user_id: request.subject_user_id.to_string(),
        assessed_at,
        assessed_by: assessed_by.to_owned(),
        status,
        erasable_targets: enumeration.erasable_targets,
        retained_carveouts: enumeration.retained_carveouts,
        ledger_event_count_matched: enumeration.ledger_event_count,
        subject_dek_present: enumeration.subject_dek_present,
        preflight_digest,
    }
}

/// Ensure a per-subject DEK exists for `subject_id`, returning the live DEK to encrypt PII under.
///
/// Idempotent: an existing non-erased DEK row is unwrapped and returned. Requires a durable store and
/// a resolvable credential key source. This is the provisioning half of the crypto-erase mechanism —
/// once the erasure workflow destroys this DEK, any PII encrypted under it (live or in backups) is
/// cryptographically irrecoverable.
#[allow(dead_code)]
pub fn provision_subject_dek(
    state: &AppState,
    subject_id: &str,
) -> Result<crate::secretstore::LiveDek, ApiError> {
    let Some(store) = &state.store else {
        return Err(ApiError::Internal(
            "subject DEK provisioning requires a durable store".to_owned(),
        ));
    };
    let crypto = state
        .provider_credentials
        .subject_dek_crypto()
        .map_err(|e| ApiError::Internal(format!("subject DEK crypto unavailable: {e}")))?;
    if let Some(row) = store
        .get_subject_key(subject_id)
        .map_err(|e| ApiError::Internal(format!("subject key read failed: {e}")))?
        && row.erased_at.is_none()
        && !row.wrapped_dek.is_empty()
    {
        let dek = crypto
            .unwrap_dek(subject_id, &row.wrapped_dek)
            .map_err(|e| ApiError::Internal(format!("subject DEK unwrap failed: {e}")))?;
        return Ok(dek);
    }
    let (wrapped, dek) = crypto
        .wrap_new_dek(subject_id)
        .map_err(|e| ApiError::Internal(format!("subject DEK generation failed: {e}")))?;
    let created_at = now_rfc3339();
    store
        .persist(|tx| tx.put_subject_key(subject_id, wrapped.as_bytes(), 1, &created_at))
        .map_err(|e| AppState::map_store_write_error("failed to persist the subject DEK", e))?;
    Ok(dek)
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/preflight`
///
/// Enumerate the subject's erasable targets + retained Art. 17(3) carve-outs and return the
/// digest-bound plan. Evidence only; nothing is destroyed.
pub async fn erasure_preflight(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
) -> Result<Json<ErasurePreflightReport>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    reject_api_key_for_destructive(&actor)?;
    let subject = UserId(user_id);
    let request = load_erasure_request(&state, DsrRequestId(request_id), subject).await?;
    let assessed_by = actor.resolve("api");
    let report = build_erasure_preflight_report(&state, &request, &assessed_by).await;
    Ok(Json(report))
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/approve`
///
/// Dual-control gate: the approver must be a distinct principal from the requester, must echo the
/// subject id, must acknowledge the carve-outs, and the supplied digest must match a fresh recompute.
pub async fn erasure_approve(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    Json(body): Json<ApproveErasureBody>,
) -> Result<Json<DsrRequestView>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    reject_api_key_for_destructive(&actor)?;
    let subject = UserId(user_id);
    let request_id = DsrRequestId(request_id);
    let request = load_erasure_request(&state, request_id, subject).await?;
    if request.status != DsrRequestStatus::Pending {
        return Err(ApiError::Conflict(
            "DSR request is not pending; erasure cannot be approved".to_owned(),
        ));
    }
    let approver = actor.resolve("api");
    // Dual control: the approver must not be the principal who created the request.
    if approver == request.created_by {
        return Err(ApiError::Unprocessable(
            "dual control: the erasure approver must be a different principal from the requester"
                .to_owned(),
        ));
    }
    if body.subject_confirmation.trim() != request.subject_user_id.to_string() {
        return Err(ApiError::Unprocessable(
            "subject_confirmation must echo the subject user id".to_owned(),
        ));
    }
    if !body.acknowledge_carveouts {
        return Err(ApiError::Unprocessable(
            "acknowledge_carveouts must be true: the retained Art. 17(3) carve-outs must be acknowledged"
                .to_owned(),
        ));
    }
    let report = build_erasure_preflight_report(&state, &request, &approver).await;
    if report.status != ErasureWorkflowStatus::ReadyForApproval {
        return Err(ApiError::Unprocessable(
            "erasure plan is not ready for approval (nothing to erase, or blocked by a legal hold)"
                .to_owned(),
        ));
    }
    if report.preflight_digest != body.preflight_digest.trim() {
        return Err(ApiError::Conflict(
            "preflight digest mismatch; the store changed since preflight — re-run preflight and review the new plan"
                .to_owned(),
        ));
    }
    let authorization = ErasureAuthorization {
        preflight_digest: report.preflight_digest,
        requested_by: request.created_by.clone(),
        approved_by: approver,
        approved_at: now_rfc3339(),
        carveouts_acknowledged: true,
    };

    let mut requests = state.dsr_requests.write().await;
    let mut request = requests
        .get(&request_id)
        .cloned()
        .ok_or(ApiError::NotFound)?;
    if request.status != DsrRequestStatus::Pending {
        return Err(ApiError::Conflict(
            "DSR request is not pending; erasure cannot be approved".to_owned(),
        ));
    }
    request.erasure_authorization = Some(authorization);
    let view = DsrRequestView::from(&request);
    requests.insert(request.id, request);
    drop(requests);
    persist_dsr_requests(&state).await?;
    Ok(Json(view))
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/erasure/execute`
///
/// The destructive step. Requires a prior distinct-principal approval bound to the same digest, and
/// re-checks the digest against a fresh recompute (anti-TOCTOU). In one ledger transaction it appends
/// the `subject.erased` attestation and destroys the subject DEK; it then physically removes the
/// subject's directory identity (write-through) and VACUUMs. The append-only ledger is never mutated,
/// so `verify()` advances Ok(n) → Ok(n+1). Outcome is capped at `partially_fulfilled` (retained
/// carve-outs remain).
pub async fn erasure_execute(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<ExecuteErasureBody>,
) -> Result<Json<DsrRequestView>, ApiError> {
    require_permission(&state, &actor, Permission::UserManage, Scope::Global).await?;
    reject_api_key_for_destructive(&actor)?;
    let subject = UserId(user_id);
    let request_id = DsrRequestId(request_id);
    let executed_by = actor.resolve("api");
    let request = load_erasure_request(&state, request_id, subject).await?;
    if request.status != DsrRequestStatus::Pending {
        return Err(ApiError::Conflict(
            "DSR request is not pending; erasure has already been completed".to_owned(),
        ));
    }
    let Some(authorization) = request.erasure_authorization.clone() else {
        return Err(ApiError::Unprocessable(
            "erasure has not been approved; POST .../erasure/approve first".to_owned(),
        ));
    };
    // Dual control invariant (belt-and-braces: approve already enforced it).
    if authorization.approved_by == authorization.requested_by {
        return Err(forbidden());
    }
    // Re-enumerate and bind: the body digest, the approved digest, and a fresh recompute must agree.
    let report = build_erasure_preflight_report(&state, &request, &executed_by).await;
    if body.preflight_digest.trim() != authorization.preflight_digest
        || report.preflight_digest != authorization.preflight_digest
    {
        return Err(ApiError::Conflict(
            "preflight digest mismatch (the store changed since approval, or a stale digest was supplied); re-run preflight and approve"
                .to_owned(),
        ));
    }
    if report.status != ErasureWorkflowStatus::ReadyForApproval {
        return Err(ApiError::Unprocessable(
            "erasure plan is no longer ready to execute".to_owned(),
        ));
    }

    let executed_at = now_rfc3339();
    let subject_id = request.subject_user_id.to_string();
    let scope = format!("user:{subject_id}");
    let dek_present = report.subject_dek_present;
    let pre_erasure_ledger_head = state.ledger.read().await.len();

    let mut techniques = vec![ERASE_TECHNIQUE_PHYSICAL.to_owned()];
    if dek_present {
        techniques.push(ERASE_TECHNIQUE_CRYPTO.to_owned());
    }
    techniques.push(ERASE_TECHNIQUE_VACUUM.to_owned());
    let erased_targets: Vec<DsrAffectedRecordSummary> = report
        .erasable_targets
        .iter()
        .map(|t| DsrAffectedRecordSummary {
            collection: t.collection.clone(),
            action: "erased".to_owned(),
            count: t.count,
        })
        .collect();

    // The digested, retained-as-JSON attestation payload (mirrors ReanchorRecord's justification).
    let attestation = serde_json::json!({
        "subject_id": subject_id,
        "dsr_request_id": request.id.to_string(),
        "requested_by": authorization.requested_by,
        "approved_by": authorization.approved_by,
        "executed_by": executed_by,
        "executed_at": executed_at,
        "technique": techniques,
        "targets": erased_targets,
        "dek_destroyed": dek_present,
        "retained_carveouts": report.retained_carveouts,
        "pre_erasure_ledger_head": pre_erasure_ledger_head,
        "ledger_event_count_matched": report.ledger_event_count_matched,
    });
    let attestation_json = serde_json::to_string(&attestation)?;

    // Reserve the subject's directory identity for erasure and validate anti-lockout/bootstrap
    // invariants before any irreversible ledger/key mutation. Keep the write lock until the
    // removal is committed so concurrent erasures cannot both observe a safe pre-removal state.
    let mut users = state.users.write().await;
    {
        let Some(target) = users.get(&subject) else {
            return Err(ApiError::NotFound);
        };
        if users.len() <= 1 {
            return Err(ApiError::Conflict(
                "não pode apagar o último utilizador".to_owned(),
            ));
        }
        if target.active && users.values().filter(|u| u.active).count() <= 1 {
            return Err(ApiError::Conflict(
                "não pode apagar o último utilizador ativo".to_owned(),
            ));
        }
        if target.active
            && target
                .role_assignments
                .iter()
                .any(RoleAssignment::is_owner_admin)
        {
            let active_owner_holders =
                count_owner_admin_holders(users.values().filter(|u| u.active).flat_map(|u| {
                    let uid = AuthzUserId(u.id.0);
                    u.role_assignments.iter().map(move |a| (uid, a))
                }));
            if !last_owner_guard(active_owner_holders) {
                return Err(ApiError::Conflict(
                    "não pode apagar o último Proprietário".to_owned(),
                ));
            }
        }
    }

    // Step 1 — append `subject.erased` + destroy the subject DEK atomically (ledger event +
    // subject_keys row, one commits-or-rolls-back transaction). Actor = subject UUID (pseudonymous
    // convention); scope `user:{uuid}` → Application chain (no genesis-kind constraint).
    let subject_erased_event_id = {
        let mut ledger = state.ledger.write().await;
        try_append_event(
            &mut ledger,
            &subject_id,
            &scope,
            SUBJECT_ERASED_KIND,
            Some(&attestation_json),
            attestation_json.as_bytes(),
        )?;
        let event_id = ledger
            .events()
            .last()
            .map(|e| e.id.to_string())
            .unwrap_or_default();
        let subject_key = subject_id.clone();
        let erased_at = executed_at.clone();
        state
            .persist_write_through(&mut ledger, 1, move |tx| {
                if dek_present {
                    tx.destroy_subject_key(&subject_key, &erased_at)?;
                }
                Ok(())
            })
            .await?;
        state.attest_latest(&attestor, &ledger).await;
        event_id
    };

    // Step 2 — physically remove the subject's directory identity, write-through (rewrites
    // `users.json` on SQLite, reconciles the `users` table on Postgres — backend-agnostic).
    users.remove(&subject);
    drop(users);
    persist_users(&state).await?;

    // Step 3 — reclaim freed pages / dead tuples so deleted PII bytes do not linger (VACUUM cannot run
    // inside a transaction). Best-effort: the DEK is already destroyed and the row already gone, so a
    // VACUUM failure must not fail the erasure; the outcome records whether it completed.
    let vacuum_completed = match &state.store {
        Some(store) => match store.read_blocking_async(|s| s.vacuum()).await {
            Ok(()) => true,
            Err(e) => {
                eprintln!("wp26-gdpr: VACUUM after erasure failed (non-fatal): {e}");
                false
            }
        },
        None => false,
    };

    // Step 4 — mark the DSR record completed (outcome capped at partially_fulfilled) + attest.
    let execution_record = ErasureExecutionRecord {
        executed_by: executed_by.clone(),
        executed_at: executed_at.clone(),
        subject_erased_event_id,
        techniques,
        erased_targets: erased_targets.clone(),
        retained_carveouts: report.retained_carveouts,
        dek_destroyed: dek_present,
        vacuum_completed,
        pre_erasure_ledger_head,
        ledger_event_count_matched: report.ledger_event_count_matched,
    };
    let view = {
        let mut requests = state.dsr_requests.write().await;
        let mut request = requests
            .get(&request_id)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        request.status = DsrRequestStatus::Completed;
        request.completed_at = Some(executed_at.clone());
        request.completed_by = Some(executed_by.clone());
        request.outcome = Some(DsrExecutionOutcome::PartiallyFulfilled);
        request.executed_at = Some(executed_at.clone());
        request.executed_by = Some(executed_by.clone());
        request.affected_records = erased_targets;
        request.erasure_execution = Some(execution_record);
        let view = DsrRequestView::from(&request);
        requests.insert(request.id, request);
        view
    };
    persist_dsr_requests(&state).await?;
    Ok(Json(view))
}

// =================================================================================================
// wp26-gdpr: append-only ANNOTATION remedy (rectification + restriction/objection).
//
// This is the STANDARD data-subject remedy for PII embedded in sealed acts / books / signed legal
// documents: those records carry a statutory retention obligation (GDPR Art. 17(3)(b)) and rewriting
// them would break their signatures, so they are never erased. Instead a correction (rectification)
// or a restriction-of-processing / objection marker is recorded as a NEW append-only ledger event
// linked to the record. The sealed/signed payload is never touched — signatures stay valid — and the
// ledger only ever grows, so `verify()` advances Ok(n) → Ok(n+1). Destructive erasure (above) is the
// narrow exception for genuinely non-legally-required PII.
// =================================================================================================

#[derive(Deserialize)]
pub struct SubjectAnnotationBody {
    /// The rectification correction text, or the restriction / objection reason.
    #[serde(default)]
    pub note: Option<String>,
    /// Optional target scope the annotation is recorded against — an act / entity / book scope
    /// (`entity:{id}/book:{id}/act:{id}`, `entity:{id}`, …) so the note is discoverable alongside the
    /// sealed record. Defaults to the subject's `user:{uuid}` scope (the Application chain).
    #[serde(default)]
    pub target_scope: Option<String>,
    /// Optional field being rectified / objected to (e.g. `display_name`).
    #[serde(default)]
    pub field: Option<String>,
}

#[derive(Serialize)]
pub struct SubjectAnnotationView {
    pub subject_user_id: String,
    pub dsr_request_id: String,
    /// `rectification` or `restriction`.
    pub annotation: String,
    pub event_kind: String,
    pub event_id: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub note: String,
    pub noted_by: String,
    pub noted_at: String,
    /// The append-only ledger head after the annotation (proves the ledger only grew).
    pub ledger_length: usize,
}

/// Validate and default the annotation target scope. A caller-supplied scope must be a recognised
/// scope-grammar string (act / book / entity / a bare uuid / an app keyword); anything path-like or
/// empty is rejected. When absent, the annotation is scoped to the subject's `user:{uuid}` chain.
fn resolve_annotation_scope(
    subject_user_id: &UserId,
    target_scope: Option<String>,
) -> Result<String, ApiError> {
    match target_scope
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        None => Ok(format!("user:{subject_user_id}")),
        Some(scope) => {
            if scope.len() > 256 || scope.contains("..") || scope.contains(['\\', '\n', '\r']) {
                return Err(ApiError::Unprocessable("invalid target_scope".to_owned()));
            }
            Ok(scope)
        }
    }
}

async fn record_subject_annotation(
    state: &AppState,
    subject: UserId,
    request_id: DsrRequestId,
    annotation_label: &str,
    body: SubjectAnnotationBody,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<Json<SubjectAnnotationView>, ApiError> {
    // The append-only event kind is fixed by the remedy (rectification vs restriction/objection).
    let kind = match annotation_label {
        "rectification" => SUBJECT_RECTIFICATION_KIND,
        _ => SUBJECT_PROCESSING_RESTRICTED_KIND,
    };
    require_permission(state, actor, Permission::UserManage, Scope::Global).await?;
    // The DSR must exist and belong to the subject (audit linkage for the annotation).
    {
        let requests = state.dsr_requests.read().await;
        let request = requests.get(&request_id).ok_or(ApiError::NotFound)?;
        if request.subject_user_id != subject {
            return Err(ApiError::NotFound);
        }
    }
    let note = clean_required(body.note.as_deref().unwrap_or_default(), "note")?;
    if note.chars().count() > MAX_DSR_EXECUTION_NOTE_CHARS {
        return Err(ApiError::Unprocessable(format!(
            "note must be at most {MAX_DSR_EXECUTION_NOTE_CHARS} characters"
        )));
    }
    let field = clean_optional_bounded(body.field, "field", MAX_DSR_AFFECTED_FIELD_CHARS)?;
    let scope = resolve_annotation_scope(&subject, body.target_scope)?;
    let noted_by = actor.resolve("api");
    let noted_at = now_rfc3339();

    // The digested, retained-as-JSON annotation payload. Records the correction / restriction against
    // the record WITHOUT touching any sealed / signed content.
    let payload = serde_json::json!({
        "subject_id": subject.to_string(),
        "dsr_request_id": request_id.to_string(),
        "annotation": annotation_label,
        "field": field,
        "note": note,
        "scope": scope,
        "noted_by": noted_by,
        "noted_at": noted_at,
    });
    let payload_json = serde_json::to_string(&payload)?;
    let payload_digest = sha256_hex(payload_json.as_bytes());
    let justification =
        format!("{annotation_label} annotation recorded; payload_digest={payload_digest}");

    let (event_id, ledger_length) = {
        let mut ledger = state.ledger.write().await;
        try_append_event(
            &mut ledger,
            &noted_by,
            &scope,
            kind,
            Some(&justification),
            payload_json.as_bytes(),
        )?;
        let event_id = ledger
            .events()
            .last()
            .map(|e| e.id.to_string())
            .unwrap_or_default();
        state
            .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
            .await?;
        state.attest_latest(attestor, &ledger).await;
        (event_id, ledger.len())
    };

    Ok(Json(SubjectAnnotationView {
        subject_user_id: subject.to_string(),
        dsr_request_id: request_id.to_string(),
        annotation: annotation_label.to_owned(),
        event_kind: kind.to_owned(),
        event_id,
        scope,
        field,
        note,
        noted_by,
        noted_at,
        ledger_length,
    }))
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/rectification`
///
/// Record an append-only rectification note against the subject's records (the standard Art. 16 /
/// Art. 17(3)(b) remedy). Never modifies any sealed / signed payload — signatures stay valid.
pub async fn record_subject_rectification(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<SubjectAnnotationBody>,
) -> Result<Json<SubjectAnnotationView>, ApiError> {
    record_subject_annotation(
        &state,
        UserId(user_id),
        DsrRequestId(request_id),
        "rectification",
        body,
        &actor,
        &attestor,
    )
    .await
}

/// `POST /v1/privacy/users/{user_id}/dsr-requests/{request_id}/restriction`
///
/// Record an append-only restriction-of-processing / objection marker against the subject's records
/// (GDPR Art. 18 / Art. 21). Never modifies any sealed / signed payload — signatures stay valid.
pub async fn record_subject_restriction(
    State(state): State<AppState>,
    Path((user_id, request_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(body): Json<SubjectAnnotationBody>,
) -> Result<Json<SubjectAnnotationView>, ApiError> {
    record_subject_annotation(
        &state,
        UserId(user_id),
        DsrRequestId(request_id),
        "restriction",
        body,
        &actor,
        &attestor,
    )
    .await
}

fn clean_required(raw: &str, field: &str) -> Result<String, ApiError> {
    let value = raw.trim();
    if value.is_empty() {
        Err(ApiError::Unprocessable(format!("{field} is required")))
    } else {
        Ok(value.to_owned())
    }
}

fn clean_optional(raw: Option<String>) -> Option<String> {
    raw.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    })
}

fn clean_optional_bounded(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = clean_optional(raw) else {
        return Ok(None);
    };
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    reject_sensitive_evidence_markers(&value, field)?;
    Ok(Some(value))
}

fn required_bounded_string(
    raw: Option<String>,
    field: &str,
    max_chars: usize,
) -> Result<String, ApiError> {
    let value = required_string(raw, field)?;
    if value.chars().count() > max_chars {
        return Err(ApiError::Unprocessable(format!(
            "{field} must be at most {max_chars} characters"
        )));
    }
    reject_sensitive_evidence_markers(&value, field)?;
    Ok(value)
}

fn reject_sensitive_evidence_markers(value: &str, field: &str) -> Result<(), ApiError> {
    let lower = value.to_ascii_lowercase();
    if SENSITIVE_EVIDENCE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        Err(ApiError::Unprocessable(format!(
            "{field} must not include sensitive credential field names"
        )))
    } else {
        Ok(())
    }
}

fn sanitized_strings(
    raw: Vec<String>,
    field: &str,
    require_non_empty: bool,
) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let value = item.trim();
        if value.is_empty() || out.iter().any(|existing| existing.as_str() == value) {
            continue;
        }
        out.push(value.to_owned());
    }
    if require_non_empty && out.is_empty() {
        Err(ApiError::Unprocessable(format!(
            "{field} must include at least one non-empty value"
        )))
    } else {
        Ok(out)
    }
}

fn sanitized_privacy_control_list(
    raw: Vec<String>,
    field: &str,
    require_non_empty: bool,
) -> Result<Vec<String>, ApiError> {
    if raw.len() > MAX_PRIVACY_CONTROL_LIST_ITEMS {
        return Err(ApiError::Unprocessable(format!(
            "{field} must include at most {MAX_PRIVACY_CONTROL_LIST_ITEMS} entries"
        )));
    }
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = required_bounded_string(
            Some(trimmed.to_owned()),
            field,
            MAX_PRIVACY_CONTROL_FIELD_CHARS,
        )?;
        reject_path_like_value(&value, field)?;
        if out.iter().any(|existing| existing.as_str() == value) {
            continue;
        }
        out.push(value);
    }
    if require_non_empty && out.is_empty() {
        Err(ApiError::Unprocessable(format!(
            "{field} must include at least one non-empty value"
        )))
    } else {
        Ok(out)
    }
}

fn normalize_enum(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

async fn role_assignments(state: &AppState, user: &User) -> Vec<RoleAssignmentExport> {
    let roles = state.roles.read().await;
    user.role_assignments
        .iter()
        .map(|assignment| {
            let role = roles.get(RoleId(assignment.role_id.0));
            RoleAssignmentExport {
                role_id: assignment.role_id.to_string(),
                scope: assignment.scope,
                role_name: role.map(|r| r.name.clone()),
                permissions: role
                    .map(|r| {
                        r.permission_set
                            .iter()
                            .map(|p| p.as_str().to_owned())
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect()
}

async fn ledger_refs(state: &AppState, user: &User) -> Vec<LedgerEventView> {
    let user_id = user.id.to_string();
    let user_scope = format!("user:{user_id}");
    let ledger = state.ledger.read().await;
    ledger
        .events()
        .iter()
        .filter(|event| {
            event.actor == user.username || event.actor == user_id || event.scope == user_scope
        })
        .map(LedgerEventView::from)
        .collect()
}

async fn ensure_subject_exists(state: &AppState, subject_user_id: UserId) -> Result<(), ApiError> {
    if state.users.read().await.contains_key(&subject_user_id) {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

async fn record_dsr_event(
    state: &AppState,
    view: &DsrRequestView,
    kind: &str,
    justification: &str,
    actor_name: &str,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let _requests = state.dsr_requests.write().await;
    record_dsr_event_locked(state, view, kind, justification, actor_name, attestor).await
}

async fn record_dsr_event_locked(
    state: &AppState,
    view: &DsrRequestView,
    kind: &str,
    justification: &str,
    actor_name: &str,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(view)?;
    let scope = format!("user:{}", view.subject_user_id);
    let mut ledger = state.ledger.write().await;
    try_append_event(
        &mut ledger,
        actor_name,
        &scope,
        kind,
        Some(justification),
        &bytes,
    )?;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

async fn record_privacy_event<T: Serialize>(
    state: &AppState,
    scope: &str,
    kind: &str,
    justification: &str,
    actor_name: &str,
    view: &T,
    attestor: &CurrentAttestor,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(view)?;
    let mut ledger = state.ledger.write().await;
    try_append_event(
        &mut ledger,
        actor_name,
        scope,
        kind,
        Some(justification),
        &bytes,
    )?;
    state
        .persist_write_through(&mut ledger, 1, |_| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
