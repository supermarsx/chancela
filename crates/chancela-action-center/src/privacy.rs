use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime};
use uuid::Uuid;

const PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS: i64 = 365;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DpiaRecordId(pub Uuid);

impl std::fmt::Display for DpiaRecordId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BreachPlaybookId(pub Uuid);

impl std::fmt::Display for BreachPlaybookId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferControlId(pub Uuid);

impl std::fmt::Display for TransferControlId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DpiaEvidenceKind {
    Review,
    Drill,
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
    let (status, next_review_due_at, days_until_due) =
        if input.record_status == PrivacyRecordStatus::UnderReview {
            (PrivacyAdvisoryReviewStatus::UnderReview, None, None)
        } else if let Some((last_date, _)) = input.latest_local_evidence {
            let next_due_date = last_date + Duration::days(PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS);
            let days = next_due_date.to_julian_day() - input.today.to_julian_day();
            let status = if days < 0 {
                PrivacyAdvisoryReviewStatus::Overdue
            } else if days <= i32::from(input.due_soon_days) {
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
        last_reviewed_at: input.last_reviewed_at,
        last_drill_at: input.last_drill_at,
        next_review_due_at,
        days_until_due,
        review_interval_days: PRIVACY_ADVISORY_REVIEW_INTERVAL_DAYS,
        receipt_count: input.receipt_count,
        review_receipt_count: input.review_receipt_count,
        drill_receipt_count: input.drill_receipt_count,
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
    OffsetDateTime::parse(selected, &Rfc3339)
        .ok()
        .map(|timestamp| (timestamp.date(), selected.to_owned()))
}

fn format_date(date: Date) -> String {
    let format = time::macros::format_description!("[year]-[month]-[day]");
    date.format(&format).unwrap_or_default()
}
