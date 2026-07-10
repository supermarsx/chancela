//! Local technical planning for PAdES long-term evidence renewal.
//!
//! The types in this module are a bounded checklist over evidence already inspected by this crate:
//! signature timestamp marker, DSS revocation blobs, DSS `/TU` freshness metadata, and
//! `/DocTimeStamp` imprint binding. They do not fetch revocation data, validate certificate/TSA
//! trust, decide renewal deadlines, or claim PAdES-B-LT / B-LTA / legal LTV sufficiency.

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
}

/// Build a local-only LTV renewal plan from already-inspected PAdES evidence.
pub fn plan_ltv_renewal(
    signature_timestamp_present: bool,
    dss: &DssReport,
    doc_timestamps: &DocTimeStampReport,
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
    }
}
