//! Backend-first privacy / compliance endpoints.
//!
//! DSR exports are deliberately read-only and non-secret: they reuse safe user/accountability state
//! and never serialize stored credential material. DSR requests, processor records, and DPIA
//! records are kept in memory for ephemeral states and written through to JSON sidecars when a data
//! directory is configured; each lifecycle transition is still chained into the ledger.

use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chancela_authz::{Permission, RoleId, Scope};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{authorizer, forbidden, require_permission};
use crate::dto::LedgerEventView;
use crate::error::ApiError;
use crate::try_append_event;
use crate::users::{User, UserId, UserView};

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
pub(crate) const PROCESSORS_FILE: &str = "privacy-processors.json";
pub(crate) const DPIAS_FILE: &str = "privacy-dpias.json";
pub(crate) const BREACH_PLAYBOOKS_FILE: &str = "privacy-breach-playbooks.json";
pub(crate) const TRANSFER_CONTROLS_FILE: &str = "privacy-transfer-controls.json";
pub(crate) const DSR_REQUESTS_FILE: &str = "privacy-dsr-requests.json";
pub(crate) const RETENTION_POLICIES_FILE: &str = "retention-policies.json";
pub(crate) const RETENTION_EXECUTIONS_FILE: &str = "privacy-retention-executions.json";
const MAX_DSR_EXECUTION_NOTE_CHARS: usize = 4096;
const MAX_DSR_REVIEW_CHARS: usize = 2048;
const MAX_DSR_AFFECTED_RECORDS: usize = 32;
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

struct DsrExecutionInput {
    completion_reason: Option<String>,
    outcome: Option<String>,
    execution_notes: Option<String>,
    affected_records: Option<Vec<DsrAffectedRecordInput>>,
    retention_review: Option<String>,
    legal_basis_review: Option<String>,
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
            created_at: record.created_at.clone(),
            created_by: record.created_by.clone(),
            updated_at: record.updated_at.clone(),
            updated_by: record.updated_by.clone(),
        }
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

#[derive(Debug)]
struct ValidatedRetentionExecutionRequest {
    requested_policy_id: Option<RetentionPolicyId>,
    execution_intent: RetentionExecutionIntent,
    operator_notes: Option<String>,
    evidence: Vec<RetentionOperatorEvidence>,
    approval: Option<RetentionExecutionApproval>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

pub(crate) fn write_dsr_requests_atomic(
    path: &FsPath,
    requests: &HashMap<DsrRequestId, DsrRequest>,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
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

async fn persist_retention_execution_records(state: &AppState) -> Result<(), ApiError> {
    if let Some(path) = &state.retention_execution_records_path {
        let records = state.retention_execution_records.read().await;
        write_retention_execution_records_atomic(path, &records).map_err(|e| {
            ApiError::Internal(format!(
                "failed to persist retention execution records: {e}"
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

/// `GET /v1/privacy/retention-policies/dry-run` — list recorded retention execution requests.
pub async fn list_retention_execution_records(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<RetentionExecutionRecord>>, ApiError> {
    require_privacy_record_manage(&state, &actor).await?;
    let records = state.retention_execution_records.read().await;
    let mut list: Vec<&RetentionExecutionRecord> = records.values().collect();
    list.sort_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)));
    Ok(Json(list.into_iter().cloned().collect()))
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
    let prior_execution_records = state.retention_execution_records.read().await;
    let execution_record = execution_request.map(|execution_request| {
        build_retention_execution_record(
            &actor_name,
            &candidate,
            &records,
            &matches,
            &prior_execution_records,
            execution_request,
        )
    });
    drop(prior_execution_records);
    drop(records);
    if let Some(record) = &execution_record {
        apply_execution_result_to_matches(record, &mut matches);
    }

    if let Some(record) = &execution_record {
        state
            .retention_execution_records
            .write()
            .await
            .insert(record.id.clone(), record.clone());
        persist_retention_execution_records(&state).await?;
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

async fn complete_dsr_request_inner(
    state: &AppState,
    request_id: DsrRequestId,
    expected_subject: Option<UserId>,
    execution: DsrExecutionInput,
    actor: &CurrentActor,
    attestor: &CurrentAttestor,
) -> Result<Json<DsrRequestView>, ApiError> {
    require_permission(state, actor, Permission::UserManage, Scope::Global).await?;
    let execution = validate_dsr_execution(execution)?;

    let actor_name = actor.resolve("api");
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

    let executed_at = now_rfc3339();
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
        requested_policy,
        candidate: candidate.clone(),
        matched_records_summary: retention_matched_records_summary(candidate, matches),
        legal_hold_blockers,
        operator_notes: request.operator_notes,
        audit_evidence: request.evidence,
        approval: request.approval,
        outcome,
        block_reason: block_reason.to_owned(),
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
    let requested_policy_id = requested_policy.id.as_deref()?;
    prior_execution_records
        .values()
        .filter(|record| {
            record.candidate.scope == candidate.scope
                && record.candidate.category == candidate.category
                && record.candidate.record_id == candidate.record_id
                && record.requested_policy.id.as_deref() == Some(requested_policy_id)
                && matches!(
                    record.outcome,
                    RetentionExecutionOutcome::BoundedArchiveRecorded
                        | RetentionExecutionOutcome::BoundedNoActionRecorded
                )
                && !record.execution_result.targets_acted.is_empty()
        })
        .min_by(|a, b| a.requested_at.cmp(&b.requested_at).then(a.id.cmp(&b.id)))
        .map(|record| record.id.clone())
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
    if let Some(action) = requested_policy.disposal_action {
        if execution_intent == RetentionExecutionIntent::ExecuteSupported {
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

    if matches!(ctx.outcome, RetentionExecutionOutcome::AlreadyExecuted) {
        if let Some(prior_execution_id) = ctx.prior_execution_id {
            reason_codes.push("prior_bounded_execution_found".to_owned());
            blocker_metadata.push(RetentionExecutionBlockerMetadata {
                code: "prior_bounded_execution".to_owned(),
                detail: format!("prior execution record {prior_execution_id} already acted"),
                policy_id: ctx.requested_policy.id.clone(),
            });
        }
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

fn validate_dsr_execution(input: DsrExecutionInput) -> Result<ValidatedDsrExecution, ApiError> {
    let outcome = input
        .outcome
        .as_deref()
        .map(DsrExecutionOutcome::parse)
        .transpose()?
        .unwrap_or(DsrExecutionOutcome::Fulfilled);
    Ok(ValidatedDsrExecution {
        completion_reason: clean_optional(input.completion_reason),
        outcome,
        execution_notes: clean_optional_bounded(
            input.execution_notes,
            "execution_notes",
            MAX_DSR_EXECUTION_NOTE_CHARS,
        )?,
        affected_records: sanitize_affected_records(input.affected_records)?,
        retention_review: clean_optional_bounded(
            input.retention_review,
            "retention_review",
            MAX_DSR_REVIEW_CHARS,
        )?,
        legal_basis_review: clean_optional_bounded(
            input.legal_basis_review,
            "legal_basis_review",
            MAX_DSR_REVIEW_CHARS,
        )?,
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
    state.persist_write_through(&mut ledger, 1, |_tx| Ok(()))?;
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
    state.persist_write_through(&mut ledger, 1, |_| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
