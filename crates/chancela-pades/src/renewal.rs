//! Local technical planning for PAdES long-term evidence renewal.
//!
//! The types in this module are a bounded checklist over evidence already inspected by this crate:
//! signature timestamp marker, DSS revocation blobs, DSS `/TU` freshness metadata, and
//! `/DocTimeStamp` imprint binding. They do not fetch revocation data, validate certificate/TSA
//! trust, infer renewal deadlines, or claim PAdES-B-LT / B-LTA / legal LTV sufficiency.

use crate::archive_timestamp::DocTimeStampReport;
use crate::dss::DssReport;

/// Local-only planning report for preserving and renewing embedded validation evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LtvRenewalPlan {
    /// Machine-readable reminder that this report is technical evidence planning only.
    pub scope: LtvRenewalPlanScope,
    /// Whether the CMS signature carries an `id-aa-signatureTimeStampToken` unsigned attribute.
    pub signature_timestamp_present: bool,
    /// Whether the latest DSS contains OCSP or CRL blobs.
    pub dss_revocation_evidence_present: bool,
    /// Whether at least one VRI entry carries `/TU` validation-time metadata.
    pub dss_validation_time_present: bool,
    /// Whether at least one `/DocTimeStamp` dictionary is present.
    pub doc_timestamp_present: bool,
    /// Whether every discovered `/DocTimeStamp` has a verified SHA-256 imprint binding.
    pub doc_timestamp_imprints_valid: bool,
    /// Missing local technical inputs for renewal planning.
    pub missing_inputs: Vec<LtvRenewalPlanInput>,
    /// Suggested next local technical action, ordered by evidence dependency.
    pub next_action: LtvRenewalPlanAction,
    /// Caller-supplied local renewal policy used to classify the deadline.
    pub policy: LtvRenewalPolicy,
    /// Local classification of the caller-supplied renewal deadline.
    pub renewal_deadline: LtvRenewalDeadline,
}

impl LtvRenewalPlan {
    /// Whether this crate found any missing local evidence input for renewal planning.
    pub fn has_local_evidence_gap(&self) -> bool {
        !self.missing_inputs.is_empty()
    }

    /// Whether all local planning inputs are present.
    ///
    /// This remains a technical fact only; callers still need external policy, trust, and renewal
    /// timing decisions before making any profile or legal sufficiency claim.
    pub fn has_all_local_planning_inputs(&self) -> bool {
        self.missing_inputs.is_empty()
    }
}

/// Caller-supplied local policy knobs for technical timestamp renewal monitoring.
///
/// This model classifies only a deadline supplied by the caller. It does not derive a deadline from
/// certificate validity, timestamp token validity, algorithm sunset policy, revocation freshness, or
/// any legal retention requirement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LtvRenewalPolicy {
    /// Current time as Unix seconds. Required for deadline classification.
    pub now_unix_seconds: Option<i64>,
    /// Caller-supplied technical renewal deadline as Unix seconds.
    pub renewal_deadline_unix_seconds: Option<i64>,
    /// Optional warning window before the deadline. Defaults to zero seconds when absent.
    pub due_soon_window_seconds: Option<u64>,
}

/// Classification of a caller-supplied local renewal deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LtvRenewalDeadline {
    /// Caller-supplied technical renewal deadline as Unix seconds.
    pub deadline_unix_seconds: Option<i64>,
    /// Seconds until the deadline. Negative means the deadline is past.
    pub seconds_until_deadline: Option<i64>,
    /// High-level local status.
    pub status: LtvRenewalDeadlineStatus,
}

impl LtvRenewalDeadline {
    fn classify(policy: LtvRenewalPolicy) -> Self {
        let Some(deadline) = policy.renewal_deadline_unix_seconds else {
            return Self {
                deadline_unix_seconds: None,
                seconds_until_deadline: None,
                status: LtvRenewalDeadlineStatus::NotConfigured,
            };
        };
        let Some(now) = policy.now_unix_seconds else {
            return Self {
                deadline_unix_seconds: Some(deadline),
                seconds_until_deadline: None,
                status: LtvRenewalDeadlineStatus::NotConfigured,
            };
        };
        let seconds_until_deadline = deadline.saturating_sub(now);
        let due_soon_window =
            i64::try_from(policy.due_soon_window_seconds.unwrap_or(0)).unwrap_or(i64::MAX);
        let status = if seconds_until_deadline < 0 {
            LtvRenewalDeadlineStatus::PastDue
        } else if seconds_until_deadline == 0 {
            LtvRenewalDeadlineStatus::DueNow
        } else if seconds_until_deadline <= due_soon_window {
            LtvRenewalDeadlineStatus::DueSoon
        } else {
            LtvRenewalDeadlineStatus::Pending
        };
        Self {
            deadline_unix_seconds: Some(deadline),
            seconds_until_deadline: Some(seconds_until_deadline),
            status,
        }
    }
}

impl Default for LtvRenewalDeadline {
    fn default() -> Self {
        Self {
            deadline_unix_seconds: None,
            seconds_until_deadline: None,
            status: LtvRenewalDeadlineStatus::NotConfigured,
        }
    }
}

/// Local status for a caller-supplied technical renewal deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LtvRenewalDeadlineStatus {
    /// No complete caller-supplied deadline policy was configured.
    NotConfigured,
    /// The configured deadline is outside the due-soon window.
    Pending,
    /// The configured deadline is inside the due-soon window.
    DueSoon,
    /// The configured deadline is exactly now.
    DueNow,
    /// The configured deadline is before now.
    PastDue,
}

/// Scope marker for [`LtvRenewalPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LtvRenewalPlanScope {
    /// Only local technical evidence was inspected; no B-LT/B-LTA/legal LTV claim is made.
    LocalTechnicalEvidenceOnly,
}

/// A local technical input that is absent or not usable for renewal planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LtvRenewalPlanInput {
    /// CMS signature timestamp attribute.
    SignatureTimestamp,
    /// OCSP or CRL blobs embedded in DSS.
    DssRevocationEvidence,
    /// DSS VRI `/TU` validation-time metadata.
    DssValidationTime,
    /// PAdES `/DocTimeStamp` archive timestamp dictionary.
    DocumentTimestamp,
    /// Verifiable SHA-256 imprint binding for every discovered `/DocTimeStamp`.
    DocumentTimestampImprintBinding,
    /// A DSS `/VRI` entry keyed to this signature's CMS `/Contents` hash.
    SignatureDssVri,
    /// `/TU` validation-time metadata on this signature's DSS `/VRI` entry.
    SignatureDssValidationTime,
}

/// Next local technical action for evidence continuity planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LtvRenewalPlanAction {
    /// Add or preserve a CMS signature timestamp attribute before planning longer-term evidence.
    AddSignatureTimestamp,
    /// Embed caller-supplied OCSP/CRL material in DSS.
    EmbedDssRevocationEvidence,
    /// Record validation-time metadata in DSS VRI `/TU`.
    RecordDssValidationTime,
    /// Append a caller-supplied `/DocTimeStamp` over the current revision.
    AddDocumentTimestamp,
    /// Inspect or replace malformed/unsupported/mismatched `/DocTimeStamp` evidence.
    ReviewDocumentTimestamp,
    /// Local evidence inputs are present; schedule renewal from external policy/trust data.
    MonitorTimestampRenewal,
    /// Add or update DSS `/VRI` material for a specific signature.
    AddSignatureDssVri,
    /// Record `/TU` validation-time metadata for a specific signature's DSS `/VRI` entry.
    RecordSignatureDssValidationTime,
}

/// Minimal local evidence facts for one discovered PDF signature dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignatureRenewalEvidence {
    /// Zero-based position after sorting `/Sig` dictionaries by object id.
    pub index: usize,
    /// PDF object id of the signature dictionary.
    pub object_id: (u32, u16),
    /// End offset of this signature's signed revision.
    pub signed_revision_len: usize,
    /// Lowercase SHA-256 hex of the CMS `/Contents` DER value, used as a DSS VRI key.
    pub vri_key: Vec<u8>,
    /// Whether the CMS carries an `id-aa-signatureTimeStampToken` unsigned attribute.
    pub signature_timestamp_present: bool,
}

/// Local renewal planning for one discovered signature dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignatureLtvRenewalPlan {
    /// Zero-based position after sorting `/Sig` dictionaries by object id.
    pub index: usize,
    /// PDF object id of the signature dictionary.
    pub object_id: (u32, u16),
    /// End offset of this signature's signed revision.
    pub signed_revision_len: usize,
    /// Lowercase SHA-256 hex of the CMS `/Contents` DER value.
    pub vri_key: Vec<u8>,
    /// Whether the latest DSS has a VRI entry for this signature.
    pub dss_vri_present: bool,
    /// Whether this signature's VRI entry carries `/TU` validation-time metadata.
    pub dss_vri_validation_time_present: bool,
    /// Local technical renewal plan for this signature and document timestamp state.
    pub plan: LtvRenewalPlan,
}

/// Local technical renewal planning across every discovered signature dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultiSignatureLtvRenewalPlan {
    /// Machine-readable reminder that this report is technical evidence planning only.
    pub scope: LtvRenewalPlanScope,
    /// Number of discovered `/Sig` dictionaries covered by this plan.
    pub signature_count: usize,
    /// Per-signature local technical renewal plans.
    pub signatures: Vec<SignatureLtvRenewalPlan>,
    /// Signature indexes whose local technical evidence inputs are incomplete.
    pub signatures_with_local_evidence_gaps: Vec<usize>,
    /// Suggested next local technical action across all signatures.
    pub next_action: LtvRenewalPlanAction,
    /// Caller-supplied local renewal policy used to classify the deadline.
    pub policy: LtvRenewalPolicy,
    /// Local classification of the caller-supplied renewal deadline.
    pub renewal_deadline: LtvRenewalDeadline,
}

impl MultiSignatureLtvRenewalPlan {
    /// Whether any signature has a missing local evidence input.
    pub fn has_local_evidence_gap(&self) -> bool {
        !self.signatures_with_local_evidence_gaps.is_empty()
    }
}

/// Build a local-only LTV renewal plan from already-inspected PAdES evidence.
pub fn plan_ltv_renewal(
    signature_timestamp_present: bool,
    dss: &DssReport,
    doc_timestamps: &DocTimeStampReport,
) -> LtvRenewalPlan {
    plan_ltv_renewal_with_policy(
        signature_timestamp_present,
        dss,
        doc_timestamps,
        LtvRenewalPolicy::default(),
    )
}

/// Build a local-only LTV renewal plan with caller-supplied deadline classification.
pub fn plan_ltv_renewal_with_policy(
    signature_timestamp_present: bool,
    dss: &DssReport,
    doc_timestamps: &DocTimeStampReport,
    policy: LtvRenewalPolicy,
) -> LtvRenewalPlan {
    let dss_revocation_evidence_present = dss.has_revocation_evidence();
    let dss_validation_time_present = dss.has_vri_tu();
    let doc_timestamp_present = doc_timestamps.present;
    let doc_timestamp_imprints_valid = doc_timestamp_present && doc_timestamps.all_imprints_valid();

    let mut missing_inputs = Vec::new();
    if !signature_timestamp_present {
        missing_inputs.push(LtvRenewalPlanInput::SignatureTimestamp);
    }
    if !dss_revocation_evidence_present {
        missing_inputs.push(LtvRenewalPlanInput::DssRevocationEvidence);
    }
    if !dss_validation_time_present {
        missing_inputs.push(LtvRenewalPlanInput::DssValidationTime);
    }
    if !doc_timestamp_present {
        missing_inputs.push(LtvRenewalPlanInput::DocumentTimestamp);
    } else if !doc_timestamp_imprints_valid {
        missing_inputs.push(LtvRenewalPlanInput::DocumentTimestampImprintBinding);
    }

    let next_action = if doc_timestamp_present && !doc_timestamp_imprints_valid {
        LtvRenewalPlanAction::ReviewDocumentTimestamp
    } else if !signature_timestamp_present {
        LtvRenewalPlanAction::AddSignatureTimestamp
    } else if !dss_revocation_evidence_present {
        LtvRenewalPlanAction::EmbedDssRevocationEvidence
    } else if !dss_validation_time_present {
        LtvRenewalPlanAction::RecordDssValidationTime
    } else if !doc_timestamp_present {
        LtvRenewalPlanAction::AddDocumentTimestamp
    } else {
        LtvRenewalPlanAction::MonitorTimestampRenewal
    };

    LtvRenewalPlan {
        scope: LtvRenewalPlanScope::LocalTechnicalEvidenceOnly,
        signature_timestamp_present,
        dss_revocation_evidence_present,
        dss_validation_time_present,
        doc_timestamp_present,
        doc_timestamp_imprints_valid,
        missing_inputs,
        next_action,
        policy,
        renewal_deadline: LtvRenewalDeadline::classify(policy),
    }
}

/// Build a local-only renewal plan for every discovered signature dictionary.
pub fn plan_multi_signature_ltv_renewal(
    signatures: Vec<SignatureRenewalEvidence>,
    dss: &DssReport,
    doc_timestamps: &DocTimeStampReport,
    policy: LtvRenewalPolicy,
) -> MultiSignatureLtvRenewalPlan {
    let renewal_deadline = LtvRenewalDeadline::classify(policy);
    let mut signature_plans = Vec::with_capacity(signatures.len());
    let mut signatures_with_local_evidence_gaps = Vec::new();

    for signature in signatures {
        let dss_vri_present = dss.vri_keys.iter().any(|key| key == &signature.vri_key);
        let dss_vri_validation_time_present = dss_vri_present && dss.has_vri_tu();
        let mut plan = plan_ltv_renewal_with_policy(
            signature.signature_timestamp_present,
            dss,
            doc_timestamps,
            policy,
        );

        if dss.has_revocation_evidence() && !dss_vri_present {
            plan.missing_inputs
                .push(LtvRenewalPlanInput::SignatureDssVri);
            plan.next_action = LtvRenewalPlanAction::AddSignatureDssVri;
        } else if dss_vri_present && !dss_vri_validation_time_present {
            plan.missing_inputs
                .retain(|input| *input != LtvRenewalPlanInput::DssValidationTime);
            plan.missing_inputs
                .push(LtvRenewalPlanInput::SignatureDssValidationTime);
            if plan.next_action == LtvRenewalPlanAction::RecordDssValidationTime {
                plan.next_action = LtvRenewalPlanAction::RecordSignatureDssValidationTime;
            }
        }

        if plan.has_local_evidence_gap() {
            signatures_with_local_evidence_gaps.push(signature.index);
        }
        signature_plans.push(SignatureLtvRenewalPlan {
            index: signature.index,
            object_id: signature.object_id,
            signed_revision_len: signature.signed_revision_len,
            vri_key: signature.vri_key,
            dss_vri_present,
            dss_vri_validation_time_present,
            plan,
        });
    }

    let next_action = signature_plans
        .iter()
        .find(|signature| signature.plan.has_local_evidence_gap())
        .map(|signature| signature.plan.next_action)
        .unwrap_or(LtvRenewalPlanAction::MonitorTimestampRenewal);

    MultiSignatureLtvRenewalPlan {
        scope: LtvRenewalPlanScope::LocalTechnicalEvidenceOnly,
        signature_count: signature_plans.len(),
        signatures: signature_plans,
        signatures_with_local_evidence_gaps,
        next_action,
        policy,
        renewal_deadline,
    }
}
