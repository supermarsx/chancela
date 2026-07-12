//! Arbitrary PDF signature validation for Ferramentas.
//!
//! This endpoint is intentionally local and technical: it inspects PDF structure, validates the
//! first PAdES signature through `chancela-pades`/`chancela-cades` when present, and reports embedded
//! DSS/DocTimeStamp evidence. It does not call AMA, fetch live revocation data, build trust paths, or
//! claim legal/qualified-signature validity.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use x509_cert::der::Decode;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

pub(crate) const PDF_SIGNATURE_VALIDATION_MAX_BYTES: usize =
    crate::signature::OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES;
pub(crate) const PDF_SIGNATURE_VALIDATION_ENVELOPE_BYTES: usize =
    crate::signature::OFFICIAL_SIGNATURE_IMPORT_ENVELOPE_BYTES;

const REPORT_KIND: &str = "pdf_signature_validation";
const REPORT_SCOPE: &str = "local_technical_pdf_pades_evidence";
const LEGAL_NOTICE: &str = "Local technical PDF/PAdES evidence validation only. No AMA \
integration, live trusted-list validation, live revocation validation, qualified-status decision, or \
legal-validity conclusion is performed or claimed.";
const NOT_PERFORMED: &str = "not_performed";
const TECHNICAL_ONLY: &str = "technical_evidence_only";
const LOCAL_TECHNICAL_EVIDENCE_ONLY: &str = "local_technical_evidence_only";
const RENEWAL_PLAN_NOTICE: &str =
    "Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.";
const RENEWAL_PLAN_AVAILABLE: &str = "available";
const RENEWAL_PLAN_NOT_APPLICABLE: &str = "not_applicable";
const RENEWAL_PLAN_UNAVAILABLE: &str = "unavailable";
const RENEWAL_PLAN_ACTION_NONE: &str = "none";
const RENEWAL_PLAN_ACTION_MANUAL_REVIEW: &str = "manual_review";

/// JSON envelope accepted by `POST /v1/signature/pdf/validate`.
#[derive(Debug, Deserialize)]
struct PdfSignatureValidationRequest {
    #[serde(
        alias = "signed_pdf",
        alias = "signed_pdf_base64",
        alias = "pdf_base64",
        alias = "bytes_base64",
        alias = "data_base64",
        alias = "base64"
    )]
    content_base64: String,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default, alias = "sha256", alias = "digest_sha256")]
    declared_sha256: Option<String>,
    #[serde(default, alias = "size_bytes")]
    declared_size_bytes: Option<usize>,
}

struct PdfValidationCandidate {
    bytes: Vec<u8>,
    filename: Option<String>,
    declared_sha256: Option<String>,
    declared_size_bytes: Option<usize>,
}

/// Top-level response for `POST /v1/signature/pdf/validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfSignatureValidationResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    pub status: PdfValidationStatus,
    pub filename: Option<String>,
    pub sha256: String,
    pub size_bytes: usize,
    pub declared_sha256: Option<String>,
    pub declared_size_bytes: Option<usize>,
    pub structure: PdfStructureReport,
    pub signature: PdfSignatureTechnicalReport,
    pub trust: TrustValidationReport,
    pub revocation: RevocationValidationReport,
    pub qualification: QualificationValidationReport,
    pub findings: Vec<PdfSignatureValidationFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfValidationStatus {
    Unsigned,
    Valid,
    Invalid,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfStructureReport {
    pub is_pdf: bool,
    pub header_offset: Option<usize>,
    pub version: Option<String>,
    pub has_eof_marker: bool,
    pub has_startxref: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfSignatureTechnicalReport {
    pub status: PdfValidationStatus,
    pub validation_performed: bool,
    pub validation_error: Option<String>,
    pub signed_pdf_signal: bool,
    pub signature_marker_count: usize,
    pub byte_range_marker_count: usize,
    pub has_contents_marker: bool,
    pub pades_profile: Option<&'static str>,
    pub coverage: Option<PdfSignatureCoverageReport>,
    pub byte_range: Option<PdfByteRangeReport>,
    pub cades: Option<CadesTechnicalReport>,
    pub timestamp: SignatureTimestampReport,
    pub dss: DssTechnicalReport,
    pub doc_timestamp: DocTimeStampTechnicalReport,
    pub local_technical_renewal_plan: LocalTechnicalRenewalPlanReport,
    pub multi_signature_local_renewal_plan: MultiSignatureLocalRenewalPlanReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfSignatureCoverageReport {
    pub verdict: &'static str,
    pub covers_rendered_document: bool,
    pub reason: &'static str,
    pub status_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfByteRangeReport {
    pub byte_range: [i64; 4],
    pub covered_len: usize,
    pub total_len: usize,
    pub signed_revision_len: usize,
    pub excluded_len: Option<usize>,
    pub covers_whole_file_except_contents: bool,
    pub covers_signed_revision_except_contents: bool,
    pub has_later_incremental_updates: bool,
    pub digest_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CadesTechnicalReport {
    pub status: &'static str,
    pub attrs_ok: bool,
    pub signing_certificate_v2_present: bool,
    pub signer_cert_sha256: String,
    pub signer_cert_subject: Option<String>,
    pub signing_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureTimestampReport {
    pub signature_timestamp_present: bool,
    pub status_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DssTechnicalReport {
    pub present: bool,
    pub vri_count: usize,
    pub vri_tu_count: usize,
    pub vri_tu_keys: Vec<String>,
    pub vri_has_tu: bool,
    pub certificate_count: usize,
    pub ocsp_count: usize,
    pub crl_count: usize,
    pub revocation_evidence_present: bool,
    pub certificate_sha256: Vec<String>,
    pub ocsp_sha256: Vec<String>,
    pub crl_sha256: Vec<String>,
    pub status_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocTimeStampTechnicalReport {
    pub present: bool,
    pub count: usize,
    pub token_count: usize,
    pub token_sha256: Vec<String>,
    pub all_imprints_valid: bool,
    pub validations: Vec<DocTimeStampValidationReport>,
    pub status_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocTimeStampValidationReport {
    pub index: usize,
    pub object_id: String,
    pub byte_range: Option<[i64; 4]>,
    pub document_digest_sha256: Option<String>,
    pub token_imprint_sha256: Option<String>,
    pub token_hash_algorithm: Option<String>,
    pub status: &'static str,
    pub failure_reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalTechnicalRenewalPlanReport {
    pub status: &'static str,
    pub scope: &'static str,
    pub notice: &'static str,
    pub signature_timestamp_present: bool,
    pub dss_revocation_evidence_present: bool,
    pub dss_validation_time_present: bool,
    pub doc_timestamp_present: bool,
    pub doc_timestamp_imprints_valid: bool,
    pub missing_inputs: Vec<&'static str>,
    pub next_action: &'static str,
    pub has_local_evidence_gap: bool,
    pub all_local_planning_inputs_present: bool,
    pub production_long_term_profile_claimed: bool,
    pub legal_ltv_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MultiSignatureLocalRenewalPlanReport {
    pub status: &'static str,
    pub scope: &'static str,
    pub notice: &'static str,
    pub signature_count: usize,
    pub signatures: Vec<SignatureLocalRenewalPlanReport>,
    pub signatures_with_local_evidence_gaps: Vec<usize>,
    pub next_action: &'static str,
    pub has_local_evidence_gap: bool,
    pub all_local_planning_inputs_present: bool,
    pub production_long_term_profile_claimed: bool,
    pub legal_ltv_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureLocalRenewalPlanReport {
    pub index: usize,
    pub object_id: String,
    pub signed_revision_len: usize,
    pub vri_key_sha256: String,
    pub dss_vri_present: bool,
    pub dss_vri_validation_time_present: bool,
    pub local_technical_renewal_plan: LocalTechnicalRenewalPlanReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustValidationReport {
    pub status: &'static str,
    pub performed: bool,
    pub live_trusted_list_validation_performed: bool,
    pub ama_integration_performed: bool,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationValidationReport {
    pub status: &'static str,
    pub live_fetch_performed: bool,
    pub freshness_validation_performed: bool,
    pub embedded_evidence_inspected: bool,
    pub embedded_revocation_evidence_present: bool,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualificationValidationReport {
    pub status: &'static str,
    pub qualified_status_claimed: bool,
    pub legal_validity_claimed: bool,
    pub legal_effect_assessed: bool,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PdfSignatureValidationFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl PdfSignatureValidationFinding {
    fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "error",
            code,
            message: message.into(),
        }
    }

    fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "warning",
            code,
            message: message.into(),
        }
    }

    fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: "info",
            code,
            message: message.into(),
        }
    }
}

/// `POST /v1/signature/pdf/validate` — local technical PDF/PAdES validation for arbitrary PDFs.
///
/// Accepts a JSON/base64 envelope or raw bytes (including `application/pdf`). This is read-only and
/// never persists the uploaded artifact or validation report.
pub async fn validate_pdf_signature(
    State(state): State<AppState>,
    actor: CurrentActor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PdfSignatureValidationResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    let candidate = pdf_validation_candidate_from_request(&headers, &body)?;
    Ok(Json(validate_pdf_signature_candidate(candidate)?))
}

fn pdf_validation_candidate_from_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<PdfValidationCandidate, ApiError> {
    if request_content_type_is_json(headers) {
        let req: PdfSignatureValidationRequest = serde_json::from_slice(body).map_err(|e| {
            ApiError::Unprocessable(format!(
                "invalid PDF signature validation JSON envelope: {e}"
            ))
        })?;
        let bytes = B64
            .decode(req.content_base64.trim())
            .map_err(|e| ApiError::Unprocessable(format!("invalid base64 PDF content: {e}")))?;
        return Ok(PdfValidationCandidate {
            bytes,
            filename: non_empty(req.filename),
            declared_sha256: normalize_sha256(req.declared_sha256)?,
            declared_size_bytes: req.declared_size_bytes,
        });
    }

    Ok(PdfValidationCandidate {
        bytes: body.to_vec(),
        filename: None,
        declared_sha256: None,
        declared_size_bytes: None,
    })
}

fn validate_pdf_signature_candidate(
    candidate: PdfValidationCandidate,
) -> Result<PdfSignatureValidationResponse, ApiError> {
    let bytes = candidate.bytes;
    if bytes.len() > PDF_SIGNATURE_VALIDATION_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "PDF signature validation candidate is {} bytes; validation accepts at most {} bytes",
            bytes.len(),
            PDF_SIGNATURE_VALIDATION_MAX_BYTES
        )));
    }

    let sha256 = sha256_hex(&bytes);
    if candidate
        .declared_size_bytes
        .is_some_and(|declared| declared != bytes.len())
    {
        return Err(ApiError::Unprocessable(
            "declared PDF size does not match the received bytes".to_owned(),
        ));
    }
    if candidate
        .declared_sha256
        .as_deref()
        .is_some_and(|declared| !declared.eq_ignore_ascii_case(&sha256))
    {
        return Err(ApiError::Unprocessable(
            "declared PDF SHA-256 digest does not match the received bytes".to_owned(),
        ));
    }

    let structure = recognize_pdf(&bytes);
    let signal = signed_pdf_signal(&bytes);
    let mut findings = vec![PdfSignatureValidationFinding::info(
        "technical_scope_only",
        LEGAL_NOTICE,
    )];

    let (status, signature) = if !structure.is_pdf {
        findings.push(PdfSignatureValidationFinding::error(
            "not_pdf",
            "candidate bytes do not contain a PDF header in the first 1024 bytes",
        ));
        (
            PdfValidationStatus::Invalid,
            empty_signature_report(PdfValidationStatus::Invalid, signal, &bytes),
        )
    } else if !signal.signed_pdf_signal {
        if !structure.has_eof_marker {
            findings.push(PdfSignatureValidationFinding::warning(
                "pdf_missing_eof",
                "candidate has a PDF header but no %%EOF marker",
            ));
        }
        if !structure.has_startxref {
            findings.push(PdfSignatureValidationFinding::warning(
                "pdf_missing_startxref",
                "candidate has no startxref marker; it may not be a complete classic PDF",
            ));
        }
        findings.push(PdfSignatureValidationFinding::info(
            "unsigned_pdf",
            "no PDF signature dictionary or ByteRange markers were found",
        ));
        (
            PdfValidationStatus::Unsigned,
            empty_signature_report(PdfValidationStatus::Unsigned, signal, &bytes),
        )
    } else {
        validate_signed_pdf_evidence(&bytes, signal, &mut findings)
    };

    let trust = trust_not_performed();
    let revocation = revocation_not_performed(&signature.dss);
    let qualification = qualification_not_performed();

    Ok(PdfSignatureValidationResponse {
        report_kind: REPORT_KIND,
        scope: REPORT_SCOPE,
        legal_notice: LEGAL_NOTICE,
        status,
        filename: candidate.filename,
        sha256,
        size_bytes: bytes.len(),
        declared_sha256: candidate.declared_sha256,
        declared_size_bytes: candidate.declared_size_bytes,
        structure,
        signature,
        trust,
        revocation,
        qualification,
        findings,
    })
}

fn validate_signed_pdf_evidence(
    bytes: &[u8],
    signal: SignedPdfSignal,
    findings: &mut Vec<PdfSignatureValidationFinding>,
) -> (PdfValidationStatus, PdfSignatureTechnicalReport) {
    match chancela_pades::validate_pdf_signature(bytes) {
        Ok(report) => {
            let pades_profile = if report.has_signature_timestamp {
                "PAdES-B-T"
            } else {
                "PAdES-B-B"
            };
            let rendered_document_covered = report.coverage.covers_rendered_document();
            let status = if rendered_document_covered {
                PdfValidationStatus::Valid
            } else {
                PdfValidationStatus::Invalid
            };
            if rendered_document_covered {
                findings.push(PdfSignatureValidationFinding::info(
                    "pades_cades_cryptographic_validation_succeeded",
                    "PAdES/CAdES cryptographic validation succeeded locally and the signature coverage binds the rendered document; signer trust, qualification, and legal effect were not assessed",
                ));
            } else {
                findings.push(PdfSignatureValidationFinding::error(
                    "rendered_document_not_covered",
                    "PAdES/CAdES cryptographic validation succeeded locally, but the signature coverage does not bind the rendered document",
                ));
            }
            let dss = dss_report(&report.dss);
            let doc_timestamp = doc_timestamp_report(&report.doc_timestamps);
            if dss.revocation_evidence_present {
                findings.push(PdfSignatureValidationFinding::info(
                    "embedded_dss_revocation_evidence",
                    "embedded DSS OCSP/CRL bytes were found and counted, but revocation freshness/trust was not validated",
                ));
            }
            if doc_timestamp.present {
                findings.push(PdfSignatureValidationFinding::info(
                    "document_timestamp_evidence",
                    "embedded DocTimeStamp imprint evidence was inspected locally; TSA trust/path validation was not performed",
                ));
            }
            (
                status,
                PdfSignatureTechnicalReport {
                    status,
                    validation_performed: true,
                    validation_error: None,
                    signed_pdf_signal: true,
                    signature_marker_count: signal.signature_marker_count,
                    byte_range_marker_count: signal.byte_range_marker_count,
                    has_contents_marker: signal.has_contents_marker,
                    pades_profile: Some(pades_profile),
                    coverage: Some(coverage_report(report.coverage)),
                    byte_range: Some(valid_byte_range_report(bytes, &report)),
                    cades: Some(cades_report(&report)),
                    timestamp: SignatureTimestampReport {
                        signature_timestamp_present: report.has_signature_timestamp,
                        status_scope: TECHNICAL_ONLY,
                    },
                    dss,
                    doc_timestamp,
                    local_technical_renewal_plan: renewal_plan_report(&report.ltv_renewal_plan),
                    multi_signature_local_renewal_plan: multi_signature_renewal_plan_report(
                        &report.multi_signature_ltv_renewal_plan,
                    ),
                },
            )
        }
        Err(err) => {
            let (status, code, message) = classify_pades_error(&err);
            match status {
                PdfValidationStatus::Invalid => findings.push(
                    PdfSignatureValidationFinding::error(code, format!("{message}: {err}")),
                ),
                PdfValidationStatus::Indeterminate => findings.push(
                    PdfSignatureValidationFinding::warning(code, format!("{message}: {err}")),
                ),
                _ => findings.push(PdfSignatureValidationFinding::warning(
                    code,
                    format!("{message}: {err}"),
                )),
            }
            (
                status,
                PdfSignatureTechnicalReport {
                    status,
                    validation_performed: true,
                    validation_error: Some(err.to_string()),
                    signed_pdf_signal: true,
                    signature_marker_count: signal.signature_marker_count,
                    byte_range_marker_count: signal.byte_range_marker_count,
                    has_contents_marker: signal.has_contents_marker,
                    pades_profile: None,
                    coverage: None,
                    byte_range: signal
                        .byte_range
                        .and_then(|range| best_effort_byte_range_report(bytes, range)),
                    cades: None,
                    timestamp: SignatureTimestampReport {
                        signature_timestamp_present: false,
                        status_scope: TECHNICAL_ONLY,
                    },
                    dss: DssTechnicalReport::default(),
                    doc_timestamp: DocTimeStampTechnicalReport::default(),
                    local_technical_renewal_plan: renewal_plan_unavailable(),
                    multi_signature_local_renewal_plan: multi_signature_renewal_plan_unavailable(),
                },
            )
        }
    }
}

fn classify_pades_error(
    err: &chancela_pades::PadesError,
) -> (PdfValidationStatus, &'static str, &'static str) {
    use chancela_pades::PadesError;
    match err {
        PadesError::InvalidByteRange => (
            PdfValidationStatus::Invalid,
            "invalid_byte_range",
            "signature ByteRange is malformed or outside the file",
        ),
        PadesError::InvalidContents | PadesError::Cades(_) => (
            PdfValidationStatus::Invalid,
            "invalid_embedded_signature",
            "embedded signature bytes did not validate against the PDF ByteRange digest",
        ),
        PadesError::NoSignature => (
            PdfValidationStatus::Indeterminate,
            "signature_markers_without_parseable_signature",
            "signature-like markers were present but no parseable /Sig dictionary was found",
        ),
        PadesError::PdfParse(_)
        | PadesError::MalformedStructure(_)
        | PadesError::MissingStartxref => (
            PdfValidationStatus::Indeterminate,
            "pdf_signature_parse_indeterminate",
            "PDF parsing could not establish whether the signature is valid",
        ),
        _ => (
            PdfValidationStatus::Indeterminate,
            "pdf_signature_validation_indeterminate",
            "PAdES validation did not reach a conclusion",
        ),
    }
}

fn empty_signature_report(
    status: PdfValidationStatus,
    signal: SignedPdfSignal,
    bytes: &[u8],
) -> PdfSignatureTechnicalReport {
    PdfSignatureTechnicalReport {
        status,
        validation_performed: false,
        validation_error: None,
        signed_pdf_signal: signal.signed_pdf_signal,
        signature_marker_count: signal.signature_marker_count,
        byte_range_marker_count: signal.byte_range_marker_count,
        has_contents_marker: signal.has_contents_marker,
        pades_profile: None,
        coverage: None,
        byte_range: signal
            .byte_range
            .and_then(|range| best_effort_byte_range_report(bytes, range)),
        cades: None,
        timestamp: SignatureTimestampReport {
            signature_timestamp_present: false,
            status_scope: TECHNICAL_ONLY,
        },
        dss: DssTechnicalReport::default(),
        doc_timestamp: DocTimeStampTechnicalReport::default(),
        local_technical_renewal_plan: renewal_plan_without_report(status),
        multi_signature_local_renewal_plan: multi_signature_renewal_plan_without_report(status),
    }
}

fn coverage_report(
    coverage: chancela_pades::validate::PdfSignatureCoverage,
) -> PdfSignatureCoverageReport {
    PdfSignatureCoverageReport {
        verdict: coverage_verdict(coverage),
        covers_rendered_document: coverage.covers_rendered_document(),
        reason: coverage_reason(coverage),
        status_scope: TECHNICAL_ONLY,
    }
}

fn coverage_verdict(coverage: chancela_pades::validate::PdfSignatureCoverage) -> &'static str {
    use chancela_pades::validate::PdfSignatureCoverage;
    match coverage {
        PdfSignatureCoverage::WholeDocument => "whole_document",
        PdfSignatureCoverage::LtvAugmentedSignedRevision => "ltv_augmented_signed_revision",
        PdfSignatureCoverage::AlteredAfterSigning => "altered_after_signing",
        PdfSignatureCoverage::Malformed => "malformed",
        _ => "unknown",
    }
}

fn coverage_reason(coverage: chancela_pades::validate::PdfSignatureCoverage) -> &'static str {
    use chancela_pades::validate::PdfSignatureCoverage;
    match coverage {
        PdfSignatureCoverage::WholeDocument => {
            "signature ByteRange covers the rendered document except the signature Contents bytes"
        }
        PdfSignatureCoverage::LtvAugmentedSignedRevision => {
            "later incremental updates were classified as local technical PAdES evidence only"
        }
        PdfSignatureCoverage::AlteredAfterSigning => {
            "later incremental updates can alter the rendered document and are outside the signature coverage"
        }
        PdfSignatureCoverage::Malformed => {
            "signature ByteRange does not support a rendered-document coverage claim"
        }
        _ => "coverage verdict is not recognized by this API version",
    }
}

fn valid_byte_range_report(
    bytes: &[u8],
    report: &chancela_pades::PdfSignatureReport,
) -> PdfByteRangeReport {
    let excluded_len = byte_range_excluded_len(report.byte_range);
    PdfByteRangeReport {
        byte_range: report.byte_range,
        covered_len: report.covered_len,
        total_len: report.total_len,
        signed_revision_len: report.signed_revision_len,
        excluded_len,
        covers_whole_file_except_contents: report.covers_whole_file_except_contents,
        covers_signed_revision_except_contents: report.covers_signed_revision_except_contents,
        has_later_incremental_updates: report.has_later_incremental_updates,
        digest_sha256: Some(byte_range_digest_hex(bytes, report.byte_range)),
    }
}

fn best_effort_byte_range_report(bytes: &[u8], range: [i64; 4]) -> Option<PdfByteRangeReport> {
    let [s1, l1, s2, l2] = range;
    let s1 = usize::try_from(s1).ok()?;
    let l1 = usize::try_from(l1).ok()?;
    let s2 = usize::try_from(s2).ok()?;
    let l2 = usize::try_from(l2).ok()?;
    let e1 = s1.checked_add(l1)?;
    let e2 = s2.checked_add(l2)?;
    let covered_len = l1.checked_add(l2)?;
    let excluded_len = s2.checked_sub(e1);
    let total_len = bytes.len();
    let in_bounds = !bytes.is_empty() && e1 <= total_len && e2 <= total_len;
    Some(PdfByteRangeReport {
        byte_range: range,
        covered_len,
        total_len,
        signed_revision_len: e2,
        excluded_len,
        covers_whole_file_except_contents: s1 == 0 && e1 <= s2 && e2 == total_len,
        covers_signed_revision_except_contents: s1 == 0 && e1 <= s2,
        has_later_incremental_updates: e2 < total_len,
        digest_sha256: in_bounds.then(|| byte_range_digest_hex(bytes, range)),
    })
}

fn byte_range_excluded_len(range: [i64; 4]) -> Option<usize> {
    let [s1, l1, s2, _l2] = range;
    let s1 = usize::try_from(s1).ok()?;
    let l1 = usize::try_from(l1).ok()?;
    let s2 = usize::try_from(s2).ok()?;
    s2.checked_sub(s1.checked_add(l1)?)
}

fn byte_range_digest_hex(bytes: &[u8], range: [i64; 4]) -> String {
    let [s1, l1, s2, l2] = range;
    let s1 = usize::try_from(s1).expect("validated byte range start1");
    let l1 = usize::try_from(l1).expect("validated byte range len1");
    let s2 = usize::try_from(s2).expect("validated byte range start2");
    let l2 = usize::try_from(l2).expect("validated byte range len2");
    let mut hasher = Sha256::new();
    hasher.update(&bytes[s1..s1 + l1]);
    hasher.update(&bytes[s2..s2 + l2]);
    hex(hasher.finalize())
}

fn cades_report(report: &chancela_pades::PdfSignatureReport) -> CadesTechnicalReport {
    let cades = &report.cades;
    CadesTechnicalReport {
        status: "valid",
        attrs_ok: cades.attrs_ok,
        signing_certificate_v2_present: cades.signing_certificate_v2_present,
        signer_cert_sha256: sha256_hex(&cades.signer_cert_der),
        signer_cert_subject: signer_cert_subject(&cades.signer_cert_der),
        signing_time: cades
            .signing_time
            .and_then(|value| value.format(&Rfc3339).ok()),
    }
}

fn signer_cert_subject(der: &[u8]) -> Option<String> {
    x509_cert::Certificate::from_der(der)
        .ok()
        .map(|cert| cert.tbs_certificate.subject.to_string())
}

fn dss_report(report: &chancela_pades::DssReport) -> DssTechnicalReport {
    DssTechnicalReport {
        present: report.present,
        vri_count: report.vri_count,
        vri_tu_count: report.vri_tu_count,
        vri_tu_keys: vri_keys_text(&report.vri_tu_keys),
        vri_has_tu: report.has_vri_tu(),
        certificate_count: report.certificate_count(),
        ocsp_count: report.ocsp_count(),
        crl_count: report.crl_count(),
        revocation_evidence_present: report.has_revocation_evidence(),
        certificate_sha256: hashes_hex(&report.certificate_hashes),
        ocsp_sha256: hashes_hex(&report.ocsp_hashes),
        crl_sha256: hashes_hex(&report.crl_hashes),
        status_scope: TECHNICAL_ONLY,
    }
}

impl Default for DssTechnicalReport {
    fn default() -> Self {
        Self {
            present: false,
            vri_count: 0,
            vri_tu_count: 0,
            vri_tu_keys: Vec::new(),
            vri_has_tu: false,
            certificate_count: 0,
            ocsp_count: 0,
            crl_count: 0,
            revocation_evidence_present: false,
            certificate_sha256: Vec::new(),
            ocsp_sha256: Vec::new(),
            crl_sha256: Vec::new(),
            status_scope: TECHNICAL_ONLY,
        }
    }
}

fn doc_timestamp_report(
    report: &chancela_pades::DocTimeStampReport,
) -> DocTimeStampTechnicalReport {
    DocTimeStampTechnicalReport {
        present: report.present,
        count: report.count,
        token_count: report.token_count(),
        token_sha256: hashes_hex(&report.token_hashes),
        all_imprints_valid: report.all_imprints_valid(),
        validations: report
            .validations
            .iter()
            .map(doc_timestamp_validation_report)
            .collect(),
        status_scope: TECHNICAL_ONLY,
    }
}

impl Default for DocTimeStampTechnicalReport {
    fn default() -> Self {
        Self {
            present: false,
            count: 0,
            token_count: 0,
            token_sha256: Vec::new(),
            all_imprints_valid: false,
            validations: Vec::new(),
            status_scope: TECHNICAL_ONLY,
        }
    }
}

fn doc_timestamp_validation_report(
    validation: &chancela_pades::DocTimeStampValidation,
) -> DocTimeStampValidationReport {
    DocTimeStampValidationReport {
        index: validation.index,
        object_id: format!("{} {}", validation.object_id.0, validation.object_id.1),
        byte_range: validation.byte_range,
        document_digest_sha256: validation.document_digest.as_ref().map(hex),
        token_imprint_sha256: validation
            .token_imprint
            .as_deref()
            .filter(|imprint| imprint.len() == 32)
            .map(hex),
        token_hash_algorithm: validation.token_hash_algorithm.clone(),
        status: doc_timestamp_status(validation.status),
        failure_reason: validation.failure_reason.map(doc_timestamp_failure_reason),
    }
}

fn doc_timestamp_status(status: chancela_pades::DocTimeStampSemanticStatus) -> &'static str {
    match status {
        chancela_pades::DocTimeStampSemanticStatus::Valid => "valid",
        chancela_pades::DocTimeStampSemanticStatus::Failed => "failed",
        chancela_pades::DocTimeStampSemanticStatus::Unsupported => "unsupported",
        _ => "unknown",
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

fn renewal_plan_report(plan: &chancela_pades::LtvRenewalPlan) -> LocalTechnicalRenewalPlanReport {
    LocalTechnicalRenewalPlanReport {
        status: RENEWAL_PLAN_AVAILABLE,
        scope: renewal_plan_scope(plan.scope),
        notice: RENEWAL_PLAN_NOTICE,
        signature_timestamp_present: plan.signature_timestamp_present,
        dss_revocation_evidence_present: plan.dss_revocation_evidence_present,
        dss_validation_time_present: plan.dss_validation_time_present,
        doc_timestamp_present: plan.doc_timestamp_present,
        doc_timestamp_imprints_valid: plan.doc_timestamp_imprints_valid,
        missing_inputs: plan
            .missing_inputs
            .iter()
            .copied()
            .map(renewal_plan_missing_input)
            .collect(),
        next_action: renewal_plan_next_action(plan.next_action),
        has_local_evidence_gap: plan.has_local_evidence_gap(),
        all_local_planning_inputs_present: plan.has_all_local_planning_inputs(),
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
    }
}

fn renewal_plan_without_report(status: PdfValidationStatus) -> LocalTechnicalRenewalPlanReport {
    if status == PdfValidationStatus::Unsigned {
        renewal_plan_not_applicable()
    } else {
        renewal_plan_unavailable()
    }
}

fn renewal_plan_not_applicable() -> LocalTechnicalRenewalPlanReport {
    renewal_plan_placeholder(RENEWAL_PLAN_NOT_APPLICABLE, RENEWAL_PLAN_ACTION_NONE)
}

fn renewal_plan_unavailable() -> LocalTechnicalRenewalPlanReport {
    renewal_plan_placeholder(RENEWAL_PLAN_UNAVAILABLE, RENEWAL_PLAN_ACTION_MANUAL_REVIEW)
}

fn renewal_plan_placeholder(
    status: &'static str,
    next_action: &'static str,
) -> LocalTechnicalRenewalPlanReport {
    LocalTechnicalRenewalPlanReport {
        status,
        scope: LOCAL_TECHNICAL_EVIDENCE_ONLY,
        notice: RENEWAL_PLAN_NOTICE,
        signature_timestamp_present: false,
        dss_revocation_evidence_present: false,
        dss_validation_time_present: false,
        doc_timestamp_present: false,
        doc_timestamp_imprints_valid: false,
        missing_inputs: Vec::new(),
        next_action,
        has_local_evidence_gap: false,
        all_local_planning_inputs_present: false,
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
    }
}

fn multi_signature_renewal_plan_report(
    plan: &chancela_pades::renewal::MultiSignatureLtvRenewalPlan,
) -> MultiSignatureLocalRenewalPlanReport {
    MultiSignatureLocalRenewalPlanReport {
        status: RENEWAL_PLAN_AVAILABLE,
        scope: renewal_plan_scope(plan.scope),
        notice: RENEWAL_PLAN_NOTICE,
        signature_count: plan.signature_count,
        signatures: plan
            .signatures
            .iter()
            .map(signature_renewal_plan_report)
            .collect(),
        signatures_with_local_evidence_gaps: plan.signatures_with_local_evidence_gaps.clone(),
        next_action: renewal_plan_next_action(plan.next_action),
        has_local_evidence_gap: plan.has_local_evidence_gap(),
        all_local_planning_inputs_present: !plan.has_local_evidence_gap(),
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
    }
}

fn signature_renewal_plan_report(
    plan: &chancela_pades::renewal::SignatureLtvRenewalPlan,
) -> SignatureLocalRenewalPlanReport {
    SignatureLocalRenewalPlanReport {
        index: plan.index,
        object_id: format!("{} {}", plan.object_id.0, plan.object_id.1),
        signed_revision_len: plan.signed_revision_len,
        vri_key_sha256: String::from_utf8_lossy(&plan.vri_key).into_owned(),
        dss_vri_present: plan.dss_vri_present,
        dss_vri_validation_time_present: plan.dss_vri_validation_time_present,
        local_technical_renewal_plan: renewal_plan_report(&plan.plan),
    }
}

fn multi_signature_renewal_plan_without_report(
    status: PdfValidationStatus,
) -> MultiSignatureLocalRenewalPlanReport {
    if status == PdfValidationStatus::Unsigned {
        multi_signature_renewal_plan_not_applicable()
    } else {
        multi_signature_renewal_plan_unavailable()
    }
}

fn multi_signature_renewal_plan_not_applicable() -> MultiSignatureLocalRenewalPlanReport {
    multi_signature_renewal_plan_placeholder(RENEWAL_PLAN_NOT_APPLICABLE, RENEWAL_PLAN_ACTION_NONE)
}

fn multi_signature_renewal_plan_unavailable() -> MultiSignatureLocalRenewalPlanReport {
    multi_signature_renewal_plan_placeholder(
        RENEWAL_PLAN_UNAVAILABLE,
        RENEWAL_PLAN_ACTION_MANUAL_REVIEW,
    )
}

fn multi_signature_renewal_plan_placeholder(
    status: &'static str,
    next_action: &'static str,
) -> MultiSignatureLocalRenewalPlanReport {
    MultiSignatureLocalRenewalPlanReport {
        status,
        scope: LOCAL_TECHNICAL_EVIDENCE_ONLY,
        notice: RENEWAL_PLAN_NOTICE,
        signature_count: 0,
        signatures: Vec::new(),
        signatures_with_local_evidence_gaps: Vec::new(),
        next_action,
        has_local_evidence_gap: false,
        all_local_planning_inputs_present: false,
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
    }
}

fn renewal_plan_scope(scope: chancela_pades::LtvRenewalPlanScope) -> &'static str {
    match scope {
        chancela_pades::LtvRenewalPlanScope::LocalTechnicalEvidenceOnly => {
            LOCAL_TECHNICAL_EVIDENCE_ONLY
        }
        _ => LOCAL_TECHNICAL_EVIDENCE_ONLY,
    }
}

fn renewal_plan_missing_input(input: chancela_pades::LtvRenewalPlanInput) -> &'static str {
    match input {
        chancela_pades::LtvRenewalPlanInput::SignatureTimestamp => "signature_timestamp",
        chancela_pades::LtvRenewalPlanInput::DssRevocationEvidence => "dss_revocation_evidence",
        chancela_pades::LtvRenewalPlanInput::DssValidationTime => "dss_validation_time",
        chancela_pades::LtvRenewalPlanInput::DocumentTimestamp => "document_timestamp",
        chancela_pades::LtvRenewalPlanInput::DocumentTimestampImprintBinding => {
            "document_timestamp_imprint_binding"
        }
        chancela_pades::LtvRenewalPlanInput::SignatureDssVri => "signature_dss_vri",
        chancela_pades::LtvRenewalPlanInput::SignatureDssValidationTime => {
            "signature_dss_validation_time"
        }
        _ => "unknown",
    }
}

fn renewal_plan_next_action(action: chancela_pades::LtvRenewalPlanAction) -> &'static str {
    match action {
        chancela_pades::LtvRenewalPlanAction::AddSignatureTimestamp => "add_signature_timestamp",
        chancela_pades::LtvRenewalPlanAction::EmbedDssRevocationEvidence => {
            "embed_dss_revocation_evidence"
        }
        chancela_pades::LtvRenewalPlanAction::RecordDssValidationTime => {
            "record_dss_validation_time"
        }
        chancela_pades::LtvRenewalPlanAction::AddDocumentTimestamp => "add_document_timestamp",
        chancela_pades::LtvRenewalPlanAction::ReviewDocumentTimestamp => {
            "review_document_timestamp"
        }
        chancela_pades::LtvRenewalPlanAction::MonitorTimestampRenewal => {
            "monitor_timestamp_renewal"
        }
        chancela_pades::LtvRenewalPlanAction::AddSignatureDssVri => "add_signature_dss_vri",
        chancela_pades::LtvRenewalPlanAction::RecordSignatureDssValidationTime => {
            "record_signature_dss_validation_time"
        }
        _ => RENEWAL_PLAN_ACTION_MANUAL_REVIEW,
    }
}

fn trust_not_performed() -> TrustValidationReport {
    TrustValidationReport {
        status: NOT_PERFORMED,
        performed: false,
        live_trusted_list_validation_performed: false,
        ama_integration_performed: false,
        message: "No AMA validator integration, EU trusted-list lookup, trust-path building, or signer trust decision was performed.",
    }
}

fn revocation_not_performed(dss: &DssTechnicalReport) -> RevocationValidationReport {
    RevocationValidationReport {
        status: NOT_PERFORMED,
        live_fetch_performed: false,
        freshness_validation_performed: false,
        embedded_evidence_inspected: dss.present,
        embedded_revocation_evidence_present: dss.revocation_evidence_present,
        message: "Embedded OCSP/CRL bytes are counted when present, but no live OCSP/CRL fetch, freshness validation, certificate path validation, or revocation trust decision was performed.",
    }
}

fn qualification_not_performed() -> QualificationValidationReport {
    QualificationValidationReport {
        status: NOT_PERFORMED,
        qualified_status_claimed: false,
        legal_validity_claimed: false,
        legal_effect_assessed: false,
        message: "This response does not determine qualified electronic signature status and does not assert legal validity.",
    }
}

#[derive(Debug, Clone, Copy)]
struct SignedPdfSignal {
    signed_pdf_signal: bool,
    signature_marker_count: usize,
    byte_range_marker_count: usize,
    has_contents_marker: bool,
    byte_range: Option<[i64; 4]>,
}

fn signed_pdf_signal(bytes: &[u8]) -> SignedPdfSignal {
    let signature_marker_count = count_signature_markers(bytes);
    let byte_range_marker_count = count_bytes(bytes, b"/ByteRange");
    SignedPdfSignal {
        signed_pdf_signal: signature_marker_count > 0 || byte_range_marker_count > 0,
        signature_marker_count,
        byte_range_marker_count,
        has_contents_marker: find_bytes(bytes, b"/Contents").is_some(),
        byte_range: parse_byte_range(bytes),
    }
}

fn count_signature_markers(bytes: &[u8]) -> usize {
    count_bytes(bytes, b"/Type/Sig") + count_bytes(bytes, b"/Type /Sig")
}

fn recognize_pdf(bytes: &[u8]) -> PdfStructureReport {
    let header = pdf_header(bytes);
    PdfStructureReport {
        is_pdf: header.is_some(),
        header_offset: header.as_ref().map(|(offset, _)| *offset),
        version: header.map(|(_, version)| version),
        has_eof_marker: find_bytes(bytes, b"%%EOF").is_some(),
        has_startxref: find_bytes(bytes, b"startxref").is_some(),
    }
}

fn pdf_header(bytes: &[u8]) -> Option<(usize, String)> {
    let limit = bytes.len().min(1024);
    let offset = find_bytes(&bytes[..limit], b"%PDF-")?;
    let start = offset + b"%PDF-".len();
    let mut end = start;
    while end < bytes.len() && matches!(bytes[end], b'0'..=b'9' | b'.') {
        end += 1;
    }
    if end == start {
        return Some((offset, String::new()));
    }
    let version = std::str::from_utf8(&bytes[start..end]).ok()?.to_owned();
    Some((offset, version))
}

fn parse_byte_range(bytes: &[u8]) -> Option<[i64; 4]> {
    let marker = find_bytes(bytes, b"/ByteRange")?;
    let mut i = marker + b"/ByteRange".len();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'[') {
        return None;
    }
    i += 1;
    let mut values = Vec::with_capacity(4);
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b']') {
            break;
        }
        let start = i;
        if bytes.get(i) == Some(&b'-') {
            i += 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || (i == start + 1 && bytes[start] == b'-') {
            return None;
        }
        let value = std::str::from_utf8(&bytes[start..i])
            .ok()?
            .parse::<i64>()
            .ok()?;
        values.push(value);
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) == Some(&b']') {
            break;
        }
    }
    (values.len() == 4).then(|| [values[0], values[1], values[2], values[3]])
}

fn request_content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|base| base.trim().eq_ignore_ascii_case("application/json"))
}

fn normalize_sha256(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::Unprocessable(
            "declared SHA-256 must be 64 hexadecimal characters".to_owned(),
        ));
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn hashes_hex(hashes: &[[u8; 32]]) -> Vec<String> {
    hashes.iter().map(hex).collect()
}

fn vri_keys_text(keys: &[Vec<u8>]) -> Vec<String> {
    keys.iter()
        .map(|key| String::from_utf8_lossy(key).into_owned())
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    hex(digest)
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chancela_authz::{
        OWNER_ROLE_ID, Permission, Role, RoleAssignment, RoleCatalog, RoleId, Scope,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{User, UserId, router};

    const MINIMAL_PDF: &[u8] = b"%PDF-1.7
1 0 obj
<< /Type /Catalog >>
endobj
xref
0 1
0000000000 65535 f
trailer
<< /Size 1 /Root 1 0 R >>
startxref
9
%%EOF
";

    async fn send(state: &AppState, req: Request<Body>) -> (StatusCode, Value) {
        let resp = router(state.clone())
            .oneshot(req)
            .await
            .expect("router responds");
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, value)
    }

    fn post_json(token: Option<&str>, body: Value) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/signature/pdf/validate")
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-chancela-session", token);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("request builds")
    }

    fn post_pdf(token: &str, bytes: &[u8]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/signature/pdf/validate")
            .header("content-type", "application/pdf")
            .header("x-chancela-session", token)
            .body(Body::from(bytes.to_vec()))
            .expect("request builds")
    }

    async fn seed_user(state: &AppState, role_id: RoleId) -> (String, UserId) {
        let uid = UserId(Uuid::new_v4());
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("created_at");
        state.users.write().await.insert(
            uid,
            User {
                id: uid,
                username: format!("user-{}", uid.0),
                display_name: "PDF Validator User".to_owned(),
                email: None,
                created_at,
                active: true,
                password_hash: None,
                attestation_key: None,
                secret_source: Default::default(),
                recovery_hash: None,
                role_assignments: vec![RoleAssignment::new(role_id, Scope::Global)],
            },
        );
        let (status, session) = send(
            state,
            Request::builder()
                .method("POST")
                .uri("/v1/session")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "user_id": uid.0 }).to_string()))
                .expect("request builds"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "session: {session}");
        (session["token"].as_str().expect("token").to_owned(), uid)
    }

    async fn owner_session(state: &AppState) -> String {
        *state.roles.write().await = RoleCatalog::seeded_defaults();
        seed_user(state, OWNER_ROLE_ID).await.0
    }

    async fn no_act_read_session(state: &AppState) -> String {
        let role_id = RoleId(Uuid::from_u128(0x70646676616c0000_0000000000000001));
        let mut catalog = RoleCatalog::seeded_defaults();
        catalog.insert(Role {
            id: role_id,
            name: "PDF validator no act read".to_owned(),
            permission_set: BTreeSet::from([Permission::EntityRead]),
            protected: false,
        });
        *state.roles.write().await = catalog;
        seed_user(state, role_id).await.0
    }

    fn assert_local_renewal_plan_guardrails(plan: &Value) {
        assert_eq!(plan["scope"], LOCAL_TECHNICAL_EVIDENCE_ONLY);
        assert_eq!(plan["notice"], RENEWAL_PLAN_NOTICE);
        assert_eq!(plan["production_long_term_profile_claimed"], false);
        assert_eq!(plan["legal_ltv_claimed"], false);
    }

    fn assert_multi_signature_local_renewal_plan_guardrails(plan: &Value) {
        assert_eq!(plan["scope"], LOCAL_TECHNICAL_EVIDENCE_ONLY);
        assert_eq!(plan["notice"], RENEWAL_PLAN_NOTICE);
        assert_eq!(plan["production_long_term_profile_claimed"], false);
        assert_eq!(plan["legal_ltv_claimed"], false);
    }

    fn append_object_override(pdf: &[u8], obj_id: u32, new_body: &str) -> Vec<u8> {
        let root_id = parse_u32_after_last(pdf, b"/Root ").expect("root object id");
        let size = parse_u32_after_last(pdf, b"/Size ").expect("trailer size");
        let prev_startxref = last_startxref(pdf).expect("startxref");
        let mut out = pdf.to_vec();
        let obj_offset = out.len() + 1;
        out.extend_from_slice(b"\n");
        out.extend_from_slice(format!("{obj_id} 0 obj\n{new_body}\nendobj\n").as_bytes());
        let xref_offset = out.len();
        out.extend_from_slice(
            format!(
                "xref\n{obj_id} 1\n{obj_offset:010} 00000 n\r\ntrailer\n<< /Size {size} /Root {root_id} 0 R /Prev {prev_startxref} >>\nstartxref\n{xref_offset}\n%%EOF\n",
            )
            .as_bytes(),
        );
        out
    }

    fn last_startxref(pdf: &[u8]) -> Option<usize> {
        let marker = rfind_bytes(pdf, b"startxref")? + b"startxref".len();
        parse_usize_at(pdf, marker)
    }

    fn parse_u32_after_last(haystack: &[u8], needle: &[u8]) -> Option<u32> {
        let start = rfind_bytes(haystack, needle)? + needle.len();
        parse_u32_at(haystack, start)
    }

    fn parse_u32_at(bytes: &[u8], start: usize) -> Option<u32> {
        let value = parse_usize_at(bytes, start)?;
        u32::try_from(value).ok()
    }

    fn parse_usize_at(bytes: &[u8], mut start: usize) -> Option<usize> {
        while matches!(bytes.get(start), Some(b' ' | b'\r' | b'\n' | b'\t')) {
            start += 1;
        }
        let mut end = start;
        while matches!(bytes.get(end), Some(byte) if byte.is_ascii_digit()) {
            end += 1;
        }
        (end > start).then(|| std::str::from_utf8(&bytes[start..end]).ok()?.parse().ok())?
    }

    fn rfind_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() || haystack.len() < needle.len() {
            return None;
        }
        haystack
            .windows(needle.len())
            .rposition(|window| window == needle)
    }

    #[tokio::test]
    async fn pdf_signature_unsigned_minimal_pdf_reports_structure() {
        let state = AppState::default();
        let token = owner_session(&state).await;

        let (status, body) = send(&state, post_pdf(&token, MINIMAL_PDF)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "unsigned");
        assert_eq!(body["structure"]["is_pdf"], true);
        assert_eq!(body["structure"]["has_eof_marker"], true);
        assert_eq!(body["structure"]["has_startxref"], true);
        assert_eq!(body["signature"]["validation_performed"], false);
        assert_eq!(body["trust"]["status"], NOT_PERFORMED);
        assert_eq!(body["qualification"]["legal_validity_claimed"], false);
        let plan = &body["signature"]["local_technical_renewal_plan"];
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_NOT_APPLICABLE);
        assert_eq!(plan["next_action"], RENEWAL_PLAN_ACTION_NONE);
        assert_eq!(plan["missing_inputs"], json!([]));
    }

    #[tokio::test]
    async fn pdf_signature_malformed_non_pdf_reports_invalid() {
        let state = AppState::default();
        let token = owner_session(&state).await;

        let (status, body) = send(&state, post_pdf(&token, b"not a pdf")).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "invalid");
        assert_eq!(body["structure"]["is_pdf"], false);
        assert!(
            body["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .any(|finding| finding["code"] == "not_pdf")
        );
    }

    #[tokio::test]
    async fn pdf_signature_json_base64_input_and_declared_fixity() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let digest = sha256_hex(MINIMAL_PDF);

        let (status, body) = send(
            &state,
            post_json(
                Some(&token),
                json!({
                    "pdf_base64": B64.encode(MINIMAL_PDF),
                    "filename": "unsigned.pdf",
                    "declared_sha256": digest,
                    "declared_size_bytes": MINIMAL_PDF.len()
                }),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "unsigned");
        assert_eq!(body["filename"], "unsigned.pdf");
        assert_eq!(body["declared_size_bytes"], MINIMAL_PDF.len());
        assert_eq!(body["declared_sha256"], sha256_hex(MINIMAL_PDF));
    }

    #[tokio::test]
    async fn pdf_signature_declared_digest_or_size_mismatch_fails_closed() {
        let state = AppState::default();
        let token = owner_session(&state).await;

        let (status, body) = send(
            &state,
            post_json(
                Some(&token),
                json!({
                    "pdf_base64": B64.encode(MINIMAL_PDF),
                    "declared_sha256": "0".repeat(64)
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body["error"].as_str().expect("error").contains("SHA-256"));

        let (status, body) = send(
            &state,
            post_json(
                Some(&token),
                json!({
                    "pdf_base64": B64.encode(MINIMAL_PDF),
                    "declared_size_bytes": MINIMAL_PDF.len() + 1
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(body["error"].as_str().expect("error").contains("size"));
    }

    #[tokio::test]
    async fn pdf_signature_route_requires_act_read_global() {
        let state = AppState::default();
        let (status, body) = send(
            &state,
            post_json(None, json!({ "pdf_base64": B64.encode(MINIMAL_PDF) })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

        let token = no_act_read_session(&state).await;
        let (status, body) = send(
            &state,
            post_json(
                Some(&token),
                json!({ "pdf_base64": B64.encode(MINIMAL_PDF) }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn pdf_signature_validation_has_no_persistence_side_effects() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let before_ledger_len = state.ledger.read().await.events().len();

        let (status, body) = send(&state, post_pdf(&token, MINIMAL_PDF)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(state.ledger.read().await.events().len(), before_ledger_len);
        assert!(state.documents.read().await.is_empty());
        assert!(state.signed_documents.read().await.is_empty());
        assert!(state.pending_signatures.read().await.is_empty());
    }

    #[tokio::test]
    async fn pdf_signature_valid_fixture_reports_pades_evidence() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-dss-local/input/bt-dss-local.pdf"
        );

        let (status, body) = send(&state, post_pdf(&token, pdf)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "valid");
        assert_eq!(body["signature"]["pades_profile"], "PAdES-B-T");
        assert_eq!(body["signature"]["cades"]["status"], "valid");
        assert!(
            body["signature"]["cades"]["signer_cert_sha256"]
                .as_str()
                .expect("cert hash")
                .len()
                == 64
        );
        assert_eq!(
            body["signature"]["timestamp"]["signature_timestamp_present"],
            true
        );
        assert_eq!(body["signature"]["dss"]["present"], true);
        assert_eq!(body["revocation"]["status"], NOT_PERFORMED);
        let plan = &body["signature"]["local_technical_renewal_plan"];
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_AVAILABLE);
        assert_eq!(plan["signature_timestamp_present"], true);
        assert_eq!(plan["dss_revocation_evidence_present"], true);
        assert_eq!(plan["dss_validation_time_present"], false);
        assert_eq!(plan["doc_timestamp_present"], false);
        assert_eq!(
            plan["missing_inputs"],
            json!(["dss_validation_time", "document_timestamp"])
        );
        assert_eq!(plan["next_action"], "record_dss_validation_time");
        assert_eq!(plan["has_local_evidence_gap"], true);
        assert_eq!(plan["all_local_planning_inputs_present"], false);
    }

    #[tokio::test]
    async fn pdf_signature_validation_rejects_cms_valid_rendered_content_alteration() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let signed = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bb-basic/input/bb-basic.pdf"
        );
        let altered = append_object_override(
            signed,
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] /Resources << >> >>",
        );
        let pades_report =
            chancela_pades::validate_pdf_signature(&altered).expect("CMS still validates");
        assert!(!pades_report.coverage.covers_rendered_document());

        let (status, body) = send(&state, post_pdf(&token, &altered)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "invalid");
        assert_eq!(body["signature"]["status"], "invalid");
        assert_eq!(body["signature"]["cades"]["status"], "valid");
        assert_eq!(
            body["signature"]["coverage"]["verdict"],
            "altered_after_signing"
        );
        assert_eq!(
            body["signature"]["coverage"]["covers_rendered_document"],
            false
        );
        assert!(
            body["signature"]["coverage"]["reason"]
                .as_str()
                .expect("coverage reason")
                .contains("rendered document")
        );
        assert_eq!(
            body["signature"]["byte_range"]["covers_signed_revision_except_contents"],
            true
        );
        assert_eq!(
            body["signature"]["byte_range"]["has_later_incremental_updates"],
            true
        );
        assert!(
            body["findings"]
                .as_array()
                .expect("findings")
                .iter()
                .any(|finding| finding["code"] == "rendered_document_not_covered")
        );
    }

    #[tokio::test]
    async fn pdf_signature_validation_reports_multi_signature_local_renewal_plan() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-dss-local/input/bt-dss-local.pdf"
        );

        let (status, body) = send(&state, post_pdf(&token, pdf)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "valid");
        let plan = &body["signature"]["multi_signature_local_renewal_plan"];
        assert_multi_signature_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_AVAILABLE);
        assert_eq!(plan["signature_count"], 1);
        assert_eq!(plan["signatures_with_local_evidence_gaps"], json!([0]));
        assert_eq!(plan["next_action"], "record_signature_dss_validation_time");
        assert_eq!(plan["has_local_evidence_gap"], true);
        assert_eq!(plan["all_local_planning_inputs_present"], false);
        let signatures = plan["signatures"].as_array().expect("signatures");
        assert_eq!(signatures.len(), 1);
        let signature = &signatures[0];
        assert_eq!(signature["index"], 0);
        assert_eq!(signature["dss_vri_present"], true);
        assert_eq!(signature["dss_vri_validation_time_present"], false);
        assert_eq!(
            signature["local_technical_renewal_plan"]["missing_inputs"],
            json!(["document_timestamp", "signature_dss_validation_time"])
        );
        assert_eq!(
            signature["local_technical_renewal_plan"]["next_action"],
            "record_signature_dss_validation_time"
        );
        assert_eq!(
            signature["local_technical_renewal_plan"]["legal_ltv_claimed"],
            false
        );
        assert_eq!(
            signature["local_technical_renewal_plan"]["production_long_term_profile_claimed"],
            false
        );
    }

    #[tokio::test]
    async fn pdf_signature_b_b_fixture_reports_local_renewal_plan_gaps() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bb-basic/input/bb-basic.pdf"
        );

        let (status, body) = send(&state, post_pdf(&token, pdf)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "valid");
        assert_eq!(body["signature"]["pades_profile"], "PAdES-B-B");
        let plan = &body["signature"]["local_technical_renewal_plan"];
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_AVAILABLE);
        assert_eq!(plan["signature_timestamp_present"], false);
        assert_eq!(plan["dss_revocation_evidence_present"], false);
        assert_eq!(plan["dss_validation_time_present"], false);
        assert_eq!(plan["doc_timestamp_present"], false);
        assert_eq!(
            plan["missing_inputs"],
            json!([
                "signature_timestamp",
                "dss_revocation_evidence",
                "dss_validation_time",
                "document_timestamp"
            ])
        );
        assert_eq!(plan["next_action"], "add_signature_timestamp");
    }

    #[tokio::test]
    async fn pdf_signature_b_t_fixture_reports_dss_as_next_local_action() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-timestamped/input/bt-timestamped.pdf"
        );

        let (status, body) = send(&state, post_pdf(&token, pdf)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "valid");
        assert_eq!(body["signature"]["pades_profile"], "PAdES-B-T");
        let plan = &body["signature"]["local_technical_renewal_plan"];
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_AVAILABLE);
        assert_eq!(plan["signature_timestamp_present"], true);
        assert_eq!(plan["dss_revocation_evidence_present"], false);
        assert_eq!(
            plan["missing_inputs"],
            json!([
                "dss_revocation_evidence",
                "dss_validation_time",
                "document_timestamp"
            ])
        );
        assert_eq!(plan["next_action"], "embed_dss_revocation_evidence");
    }

    #[tokio::test]
    async fn pdf_signature_doc_timestamp_fixture_reports_remaining_local_plan_gap() {
        let state = AppState::default();
        let token = owner_session(&state).await;
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/future-doctimestamp/input/future-doctimestamp.pdf"
        );

        let (status, body) = send(&state, post_pdf(&token, pdf)).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "valid");
        let plan = &body["signature"]["local_technical_renewal_plan"];
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan["status"], RENEWAL_PLAN_AVAILABLE);
        assert_eq!(plan["signature_timestamp_present"], true);
        assert_eq!(plan["dss_revocation_evidence_present"], true);
        assert_eq!(plan["dss_validation_time_present"], false);
        assert_eq!(plan["doc_timestamp_present"], true);
        assert_eq!(plan["doc_timestamp_imprints_valid"], true);
        assert_eq!(plan["missing_inputs"], json!(["dss_validation_time"]));
        assert_eq!(plan["next_action"], "record_dss_validation_time");
        assert_eq!(plan["has_local_evidence_gap"], true);
        assert_eq!(plan["all_local_planning_inputs_present"], false);
    }
}
