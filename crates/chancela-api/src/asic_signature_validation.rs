//! Local technical ASiC signature inspection for arbitrary ASiC ZIP containers.
//!
//! This endpoint is read-only. It classifies the ASiC member shape with `chancela-signing`, then
//! projects the local `validate_asic_container` technical report across recognised CAdES, XAdES,
//! and archive-timestamp members. It does not fetch trust/revocation material, call signing
//! providers, mutate archives, or claim legal/qualified-signature validity.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_authz::{Permission, Scope};
use chancela_signing::asic::{
    AsicBoundedProfile, AsicContainerKind, AsicDiagnosticBlocker, AsicDiagnosticBlockerId,
    AsicManifestDiagnostic, AsicProfileReport, AsicProfileShape, AsicSignatureMemberKind,
    AsicSignatureProfile,
};
use chancela_signing::{
    AsicArchiveTimestampValidation, AsicContainer, AsicEmbeddedEvidenceBlocker,
    AsicEmbeddedEvidenceIndicator, AsicSignatureValidation, AsicValidationReport, BaselineProfile,
    EvidentiaryLevel, SignatureArtifact, SignatureFormat, SigningError, SigningFamily, XadesLevel,
    extract_asic_container, sha256_content_digest, validate_asic_container, validate_signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use x509_cert::der::Decode;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::authz::require_permission;
use crate::error::ApiError;

pub(crate) const ASIC_SIGNATURE_INSPECTION_MAX_BYTES: usize =
    crate::signature::OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES;
pub(crate) const ASIC_SIGNATURE_INSPECTION_ENVELOPE_BYTES: usize =
    ASIC_SIGNATURE_INSPECTION_MAX_BYTES * 4 / 3 + 64 * 1024;

const REPORT_KIND: &str = "asic_signature_inspection";
const REPORT_SCOPE: &str = "local_technical_asic_signature_evidence";
const NOT_PERFORMED: &str = "not_performed";
const TECHNICAL_ONLY: &str = "technical_evidence_only";
const LEGAL_NOTICE: &str = "Local technical ASiC signature inspection only. No live provider call, \
trust-path validation, live TSL/TSA/OCSP/CRL fetching, revocation validation, provider approval, \
qualified-status decision, eIDAS legal-effect conclusion, production ASiC/XAdES compliance \
decision, B-LT/B-LTA/LTV claim, signing, storage mutation, or archive mutation is performed or \
claimed.";

/// JSON envelope accepted by `POST /v1/signature/asic/inspect`.
#[derive(Debug, Deserialize)]
struct AsicSignatureInspectionRequest {
    #[serde(
        alias = "asic_base64",
        alias = "asic_zip_base64",
        alias = "zip_base64",
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

struct AsicInspectionCandidate {
    bytes: Vec<u8>,
    filename: Option<String>,
    declared_sha256: Option<String>,
    declared_size_bytes: Option<usize>,
}

/// Top-level response for `POST /v1/signature/asic/inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicSignatureInspectionResponse {
    pub report_kind: &'static str,
    pub scope: &'static str,
    pub legal_notice: &'static str,
    pub status: AsicInspectionStatus,
    pub filename: Option<String>,
    pub sha256: String,
    pub size_bytes: usize,
    pub declared_sha256: Option<String>,
    pub declared_size_bytes: Option<usize>,
    pub legal_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub qualified_electronic_signature_claimed: bool,
    pub qes_claimed: bool,
    pub trust_validation: &'static str,
    pub trust_anchor_validation: &'static str,
    pub revocation_validation: &'static str,
    pub live_provider_calls: bool,
    pub live_tsl_fetching: bool,
    pub live_tsa_fetching: bool,
    pub live_ocsp_fetching: bool,
    pub live_crl_fetching: bool,
    pub provider_approval_claimed: bool,
    pub xades_validation_performed: bool,
    pub b_lt_claimed: bool,
    pub b_lta_claimed: bool,
    pub ltv_claimed: bool,
    pub production_asic_compliance_claimed: bool,
    pub production_xades_conformance_claimed: bool,
    pub eidas_legal_effect_claimed: bool,
    pub signing_performed: bool,
    pub storage_mutation_performed: bool,
    pub archive_mutation_performed: bool,
    pub technical_validation: AsicTechnicalValidationReport,
    pub profile: AsicProfileInspectionReport,
    pub cades: Option<AsicCadesValidationReport>,
    pub findings: Vec<AsicInspectionFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsicInspectionStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicProfileInspectionReport {
    pub container_kind: &'static str,
    pub mimetype: &'static str,
    pub signature_profile: &'static str,
    pub profile_shape: &'static str,
    pub bounded_profile: Option<&'static str>,
    pub bounded_supported_candidate: bool,
    pub member_paths: AsicMemberPathsReport,
    pub blockers: Vec<AsicBlockerReport>,
    pub manifest_diagnostics: Vec<AsicManifestDiagnosticReport>,
    pub signature_diagnostics: Vec<AsicSignatureDiagnosticReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicMemberPathsReport {
    pub all: Vec<String>,
    pub payloads: Vec<String>,
    pub manifests: Vec<String>,
    pub cades_signatures: Vec<String>,
    pub xades_signatures: Vec<String>,
    pub unsupported_meta_inf: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicBlockerReport {
    pub id: &'static str,
    pub message: String,
    pub member_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicManifestDiagnosticReport {
    pub path: String,
    pub size: u64,
    pub signature_references: Vec<AsicManifestSignatureReferenceReport>,
    pub data_object_references: Vec<AsicManifestDataObjectReferenceReport>,
    pub blockers: Vec<AsicBlockerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicManifestSignatureReferenceReport {
    pub uri: String,
    pub member_present: bool,
    pub member_kind: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicManifestDataObjectReferenceReport {
    pub uri: String,
    pub mime_type: Option<String>,
    pub payload_present: bool,
    pub sha256_digest: String,
    pub digest_matches: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicSignatureDiagnosticReport {
    pub path: String,
    pub member_kind: &'static str,
    pub size: u64,
    pub referenced_by_manifest_paths: Vec<String>,
    pub blockers: Vec<AsicBlockerReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicCadesValidationReport {
    pub status: &'static str,
    pub validation_performed: bool,
    pub validation_error: Option<String>,
    pub cryptographically_valid: bool,
    pub signed_content: AsicCadesSignedContentReport,
    pub signer_cert_sha256: Option<String>,
    pub signer_cert_subject: Option<String>,
    pub signing_time: Option<String>,
    pub has_signature_timestamp: bool,
    pub evidence_scope: &'static str,
    pub trust_validation: &'static str,
    pub revocation_validation: &'static str,
    pub legal_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicCadesSignedContentReport {
    pub kind: &'static str,
    pub member_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicTechnicalValidationReport {
    pub validation_performed: bool,
    pub cryptographically_valid: bool,
    pub all_signatures_valid: bool,
    pub container_failure_reasons: Vec<String>,
    pub signatures: Vec<AsicTechnicalSignatureReport>,
    pub archive_timestamps: Vec<AsicTechnicalArchiveTimestampReport>,
    pub embedded_evidence: AsicEmbeddedEvidenceReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicTechnicalSignatureReport {
    pub path: String,
    pub kind: &'static str,
    pub valid: bool,
    pub manifest_path: Option<String>,
    pub covered_data_objects: Vec<String>,
    pub signer_cert_sha256: Option<String>,
    pub signer_cert_subject: Option<String>,
    pub signing_time: Option<String>,
    pub xades_level: Option<&'static str>,
    pub has_signature_timestamp: bool,
    pub signature_timestamp_trust_validation: &'static str,
    pub failure_reasons: Vec<String>,
    pub evidence_scope: &'static str,
    pub trust_validation: &'static str,
    pub revocation_validation: &'static str,
    pub provider_validation: &'static str,
    pub provider_approval_claimed: bool,
    pub legal_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
    pub qes_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicTechnicalArchiveTimestampReport {
    pub manifest_path: String,
    pub timestamp_path: String,
    pub valid: bool,
    pub imprint_matches_manifest: bool,
    pub references_valid: bool,
    pub covered_members: Vec<String>,
    pub gen_time: Option<String>,
    pub timestamp_trust_validation: &'static str,
    pub b_lta_claimed: bool,
    pub legal_validity_claimed: bool,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicEmbeddedEvidenceReport {
    pub evidence_scope: &'static str,
    pub indicators: Vec<AsicEmbeddedEvidenceIndicatorReport>,
    pub blockers: Vec<AsicEmbeddedEvidenceBlockerReport>,
    pub trust_validation: &'static str,
    pub revocation_validation: &'static str,
    pub timestamp_trust_validation: &'static str,
    pub live_tsl_fetching: bool,
    pub live_tsa_fetching: bool,
    pub live_ocsp_fetching: bool,
    pub live_crl_fetching: bool,
    pub b_lt_claimed: bool,
    pub b_lta_claimed: bool,
    pub ltv_claimed: bool,
    pub legal_validity_claimed: bool,
    pub qualified_signature_claimed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicEmbeddedEvidenceIndicatorReport {
    pub code: String,
    pub source_path: String,
    pub evidence_kind: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicEmbeddedEvidenceBlockerReport {
    pub code: String,
    pub source_path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsicInspectionFinding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

impl AsicInspectionFinding {
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

/// `POST /v1/signature/asic/inspect` - local technical ASiC signature inspection.
///
/// Accepts a JSON/base64 envelope and never persists the uploaded artifact or report.
pub async fn inspect_asic_signature(
    State(state): State<AppState>,
    actor: CurrentActor,
    body: Bytes,
) -> Result<Json<AsicSignatureInspectionResponse>, ApiError> {
    require_permission(&state, &actor, Permission::ActRead, Scope::Global).await?;
    let candidate = asic_inspection_candidate_from_request(&body)?;
    Ok(Json(inspect_asic_signature_candidate(candidate)?))
}

fn asic_inspection_candidate_from_request(
    body: &[u8],
) -> Result<AsicInspectionCandidate, ApiError> {
    let req: AsicSignatureInspectionRequest = serde_json::from_slice(body).map_err(|e| {
        ApiError::Unprocessable(format!("invalid ASiC inspection JSON envelope: {e}"))
    })?;
    let bytes = B64
        .decode(req.content_base64.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 ASiC content: {e}")))?;
    Ok(AsicInspectionCandidate {
        bytes,
        filename: non_empty(req.filename),
        declared_sha256: normalize_sha256(req.declared_sha256)?,
        declared_size_bytes: req.declared_size_bytes,
    })
}

fn inspect_asic_signature_candidate(
    candidate: AsicInspectionCandidate,
) -> Result<AsicSignatureInspectionResponse, ApiError> {
    let bytes = candidate.bytes;
    if bytes.len() > ASIC_SIGNATURE_INSPECTION_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "ASiC inspection candidate is {} bytes; inspection accepts at most {} bytes",
            bytes.len(),
            ASIC_SIGNATURE_INSPECTION_MAX_BYTES
        )));
    }

    let sha256 = sha256_hex(&bytes);
    if candidate
        .declared_size_bytes
        .is_some_and(|declared| declared != bytes.len())
    {
        return Err(ApiError::Unprocessable(
            "declared ASiC size does not match the received bytes".to_owned(),
        ));
    }
    if candidate
        .declared_sha256
        .as_deref()
        .is_some_and(|declared| !declared.eq_ignore_ascii_case(&sha256))
    {
        return Err(ApiError::Unprocessable(
            "declared ASiC SHA-256 digest does not match the received bytes".to_owned(),
        ));
    }

    let report = chancela_signing::inspect_asic_profile(&bytes)
        .map_err(|e| ApiError::Unprocessable(format!("invalid ASiC inspection candidate: {e}")))?;
    let technical_validation = asic_technical_validation_report(&bytes);
    let xades_validation_performed = technical_validation.validation_performed
        && technical_validation
            .signatures
            .iter()
            .any(|signature| signature.kind == "xades");
    let profile = asic_profile_report(
        &report,
        xades_validation_performed && technical_validation.cryptographically_valid,
    );
    let mut findings = vec![AsicInspectionFinding::info(
        "technical_scope_only",
        LEGAL_NOTICE,
    )];

    let status = if technical_validation.validation_performed {
        if technical_validation.cryptographically_valid {
            findings.push(AsicInspectionFinding::info(
                "asic_valid_local_technical",
                "ASiC technical validation succeeded locally; signer trust, qualification, revocation, and legal effect were not assessed.",
            ));
            AsicInspectionStatus::Valid
        } else {
            findings.push(AsicInspectionFinding::error(
                "asic_invalid_local_technical",
                technical_failure_summary(&technical_validation),
            ));
            AsicInspectionStatus::Invalid
        }
    } else {
        findings.push(AsicInspectionFinding::error(
            "asic_validation_not_performed",
            technical_failure_summary(&technical_validation),
        ));
        AsicInspectionStatus::Invalid
    };

    if status != AsicInspectionStatus::Valid {
        append_blocker_findings(&report, &mut findings);
    }

    let cades = if report.is_bounded_supported_candidate() {
        Some(validate_bounded_asic_cades(&bytes))
    } else {
        None
    };
    Ok(AsicSignatureInspectionResponse {
        report_kind: REPORT_KIND,
        scope: REPORT_SCOPE,
        legal_notice: LEGAL_NOTICE,
        status,
        filename: candidate.filename,
        sha256,
        size_bytes: bytes.len(),
        declared_sha256: candidate.declared_sha256,
        declared_size_bytes: candidate.declared_size_bytes,
        legal_validity_claimed: false,
        qualified_signature_claimed: false,
        qualified_electronic_signature_claimed: false,
        qes_claimed: false,
        trust_validation: NOT_PERFORMED,
        trust_anchor_validation: NOT_PERFORMED,
        revocation_validation: NOT_PERFORMED,
        live_provider_calls: false,
        live_tsl_fetching: false,
        live_tsa_fetching: false,
        live_ocsp_fetching: false,
        live_crl_fetching: false,
        provider_approval_claimed: false,
        xades_validation_performed,
        b_lt_claimed: false,
        b_lta_claimed: false,
        ltv_claimed: false,
        production_asic_compliance_claimed: false,
        production_xades_conformance_claimed: false,
        eidas_legal_effect_claimed: false,
        signing_performed: false,
        storage_mutation_performed: false,
        archive_mutation_performed: false,
        technical_validation,
        profile,
        cades,
        findings,
    })
}

fn validate_bounded_asic_cades(bytes: &[u8]) -> AsicCadesValidationReport {
    let signed_content = match bounded_signed_content(bytes) {
        Ok(signed_content) => signed_content,
        Err(err) => {
            return AsicCadesValidationReport {
                status: "invalid",
                validation_performed: false,
                validation_error: Some(err.to_string()),
                cryptographically_valid: false,
                signed_content: AsicCadesSignedContentReport {
                    kind: "unknown",
                    member_path: String::new(),
                    sha256: String::new(),
                },
                signer_cert_sha256: None,
                signer_cert_subject: None,
                signing_time: None,
                has_signature_timestamp: false,
                evidence_scope: TECHNICAL_ONLY,
                trust_validation: NOT_PERFORMED,
                revocation_validation: NOT_PERFORMED,
                legal_validity_claimed: false,
                qualified_signature_claimed: false,
            };
        }
    };

    let artifact = SignatureArtifact {
        id: uuid::Uuid::nil(),
        slot: 0,
        family: SigningFamily::QualifiedCertificate,
        format: SignatureFormat::ASiC,
        profile: BaselineProfile::B_B,
        evidentiary_level: EvidentiaryLevel::Advanced,
        signed_at: None,
        signature: bytes.to_vec(),
        trusted_list_status: None,
        timestamp_token_der: None,
    };

    match validate_signature(&artifact, None) {
        Ok(report) => AsicCadesValidationReport {
            status: "valid",
            validation_performed: true,
            validation_error: None,
            cryptographically_valid: report.cryptographically_valid,
            signed_content,
            signer_cert_sha256: Some(sha256_hex(&report.signer_cert_der)),
            signer_cert_subject: signer_cert_subject(&report.signer_cert_der),
            signing_time: report
                .signing_time
                .and_then(|value| value.format(&Rfc3339).ok()),
            has_signature_timestamp: report.has_signature_timestamp,
            evidence_scope: TECHNICAL_ONLY,
            trust_validation: NOT_PERFORMED,
            revocation_validation: NOT_PERFORMED,
            legal_validity_claimed: false,
            qualified_signature_claimed: false,
        },
        Err(err) => AsicCadesValidationReport {
            status: "invalid",
            validation_performed: true,
            validation_error: Some(err.to_string()),
            cryptographically_valid: false,
            signed_content,
            signer_cert_sha256: None,
            signer_cert_subject: None,
            signing_time: None,
            has_signature_timestamp: false,
            evidence_scope: TECHNICAL_ONLY,
            trust_validation: NOT_PERFORMED,
            revocation_validation: NOT_PERFORMED,
            legal_validity_claimed: false,
            qualified_signature_claimed: false,
        },
    }
}

fn bounded_signed_content(bytes: &[u8]) -> Result<AsicCadesSignedContentReport, SigningError> {
    match extract_asic_container(bytes)? {
        AsicContainer::S(container) => {
            let digest = sha256_content_digest(&container.content);
            Ok(AsicCadesSignedContentReport {
                kind: "asic_s_payload",
                member_path: container.content_name,
                sha256: crate::hex::hex(&digest),
            })
        }
        AsicContainer::E(container) => {
            let digest = sha256_content_digest(&container.manifest);
            Ok(AsicCadesSignedContentReport {
                kind: "asic_e_manifest",
                member_path: chancela_signing::ASICE_MANIFEST_PATH.to_owned(),
                sha256: crate::hex::hex(&digest),
            })
        }
        _ => Err(SigningError::Asic(
            "unsupported ASiC container shape".to_owned(),
        )),
    }
}

fn asic_technical_validation_report(bytes: &[u8]) -> AsicTechnicalValidationReport {
    match validate_asic_container(bytes) {
        Ok(report) => project_asic_validation_report(&report),
        Err(err) => AsicTechnicalValidationReport {
            validation_performed: false,
            cryptographically_valid: false,
            all_signatures_valid: false,
            container_failure_reasons: vec![err.to_string()],
            signatures: Vec::new(),
            archive_timestamps: Vec::new(),
            embedded_evidence: empty_embedded_evidence_report(),
        },
    }
}

fn project_asic_validation_report(report: &AsicValidationReport) -> AsicTechnicalValidationReport {
    AsicTechnicalValidationReport {
        validation_performed: true,
        cryptographically_valid: report.is_valid(),
        all_signatures_valid: report.all_signatures_valid(),
        container_failure_reasons: report.failure_reasons.clone(),
        signatures: report
            .signatures
            .iter()
            .map(technical_signature_report)
            .collect(),
        archive_timestamps: report
            .archive_timestamps
            .iter()
            .map(technical_archive_timestamp_report)
            .collect(),
        embedded_evidence: embedded_evidence_report(report),
    }
}

fn technical_signature_report(signature: &AsicSignatureValidation) -> AsicTechnicalSignatureReport {
    AsicTechnicalSignatureReport {
        path: signature.path.clone(),
        kind: signature_member_kind(signature.kind),
        valid: signature.valid,
        manifest_path: signature.manifest_path.clone(),
        covered_data_objects: signature.covered_data_objects.clone(),
        signer_cert_sha256: signature.signer_cert_der.as_deref().map(sha256_hex),
        signer_cert_subject: signature
            .signer_cert_der
            .as_deref()
            .and_then(signer_cert_subject),
        signing_time: signature
            .signing_time
            .and_then(|value| value.format(&Rfc3339).ok()),
        xades_level: signature.xades_level.map(xades_level),
        has_signature_timestamp: signature.has_signature_timestamp,
        signature_timestamp_trust_validation: NOT_PERFORMED,
        failure_reasons: signature.failure_reasons.clone(),
        evidence_scope: TECHNICAL_ONLY,
        trust_validation: NOT_PERFORMED,
        revocation_validation: NOT_PERFORMED,
        provider_validation: NOT_PERFORMED,
        provider_approval_claimed: false,
        legal_validity_claimed: false,
        qualified_signature_claimed: false,
        qes_claimed: false,
    }
}

fn technical_archive_timestamp_report(
    archive: &AsicArchiveTimestampValidation,
) -> AsicTechnicalArchiveTimestampReport {
    AsicTechnicalArchiveTimestampReport {
        manifest_path: archive.manifest_path.clone(),
        timestamp_path: archive.timestamp_path.clone(),
        valid: archive.valid,
        imprint_matches_manifest: archive.imprint_matches_manifest,
        references_valid: archive.references_valid,
        covered_members: archive.covered_members.clone(),
        gen_time: archive
            .gen_time
            .and_then(|value| value.format(&Rfc3339).ok()),
        timestamp_trust_validation: NOT_PERFORMED,
        b_lta_claimed: false,
        legal_validity_claimed: false,
        failure_reasons: archive.failure_reasons.clone(),
    }
}

fn embedded_evidence_report(report: &AsicValidationReport) -> AsicEmbeddedEvidenceReport {
    AsicEmbeddedEvidenceReport {
        evidence_scope: TECHNICAL_ONLY,
        indicators: report
            .embedded_evidence_indicators
            .iter()
            .map(embedded_evidence_indicator_report)
            .collect(),
        blockers: report
            .embedded_evidence_blockers
            .iter()
            .map(embedded_evidence_blocker_report)
            .collect(),
        trust_validation: NOT_PERFORMED,
        revocation_validation: NOT_PERFORMED,
        timestamp_trust_validation: NOT_PERFORMED,
        live_tsl_fetching: false,
        live_tsa_fetching: false,
        live_ocsp_fetching: false,
        live_crl_fetching: false,
        b_lt_claimed: false,
        b_lta_claimed: false,
        ltv_claimed: false,
        legal_validity_claimed: false,
        qualified_signature_claimed: false,
    }
}

fn empty_embedded_evidence_report() -> AsicEmbeddedEvidenceReport {
    AsicEmbeddedEvidenceReport {
        evidence_scope: TECHNICAL_ONLY,
        indicators: Vec::new(),
        blockers: Vec::new(),
        trust_validation: NOT_PERFORMED,
        revocation_validation: NOT_PERFORMED,
        timestamp_trust_validation: NOT_PERFORMED,
        live_tsl_fetching: false,
        live_tsa_fetching: false,
        live_ocsp_fetching: false,
        live_crl_fetching: false,
        b_lt_claimed: false,
        b_lta_claimed: false,
        ltv_claimed: false,
        legal_validity_claimed: false,
        qualified_signature_claimed: false,
    }
}

fn embedded_evidence_indicator_report(
    indicator: &AsicEmbeddedEvidenceIndicator,
) -> AsicEmbeddedEvidenceIndicatorReport {
    AsicEmbeddedEvidenceIndicatorReport {
        code: indicator.code.clone(),
        source_path: indicator.source_path.clone(),
        evidence_kind: indicator.evidence_kind.clone(),
        message: indicator.message.clone(),
    }
}

fn embedded_evidence_blocker_report(
    blocker: &AsicEmbeddedEvidenceBlocker,
) -> AsicEmbeddedEvidenceBlockerReport {
    AsicEmbeddedEvidenceBlockerReport {
        code: blocker.code.clone(),
        source_path: blocker.source_path.clone(),
        message: blocker.message.clone(),
    }
}

fn technical_failure_summary(report: &AsicTechnicalValidationReport) -> String {
    let mut reasons = report.container_failure_reasons.clone();
    for signature in &report.signatures {
        reasons.extend(
            signature
                .failure_reasons
                .iter()
                .map(|reason| format!("{}: {reason}", signature.path)),
        );
    }
    for archive in &report.archive_timestamps {
        reasons.extend(
            archive
                .failure_reasons
                .iter()
                .map(|reason| format!("{}: {reason}", archive.manifest_path)),
        );
    }

    if reasons.is_empty() {
        "ASiC technical validation failed locally".to_owned()
    } else {
        reasons.join("; ")
    }
}

fn asic_profile_report(
    report: &AsicProfileReport,
    suppress_validated_xades_legacy_blocker: bool,
) -> AsicProfileInspectionReport {
    AsicProfileInspectionReport {
        container_kind: container_kind(report.container_kind),
        mimetype: report.mimetype,
        signature_profile: signature_profile(report.signature_profile),
        profile_shape: profile_shape(report.profile_shape),
        bounded_profile: report.bounded_profile.map(bounded_profile),
        bounded_supported_candidate: report.is_bounded_supported_candidate(),
        member_paths: AsicMemberPathsReport {
            all: report.member_names.clone(),
            payloads: report.payload_paths.clone(),
            manifests: report.manifest_paths.clone(),
            cades_signatures: report.cades_signature_paths.clone(),
            xades_signatures: report.xades_signature_paths.clone(),
            unsupported_meta_inf: report.unsupported_meta_inf_paths.clone(),
        },
        blockers: report
            .blocker_details
            .iter()
            .filter(|blocker| {
                !suppress_validated_xades_legacy_blocker
                    || blocker.id != AsicDiagnosticBlockerId::XadesNotSupported
            })
            .map(blocker_report)
            .collect(),
        manifest_diagnostics: report
            .manifest_diagnostics
            .iter()
            .map(manifest_diagnostic_report)
            .collect(),
        signature_diagnostics: report
            .signature_diagnostics
            .iter()
            .map(|signature| AsicSignatureDiagnosticReport {
                path: signature.path.clone(),
                member_kind: signature_member_kind(signature.member_kind),
                size: signature.size,
                referenced_by_manifest_paths: signature.referenced_by_manifest_paths.clone(),
                blockers: signature.blockers.iter().map(blocker_report).collect(),
            })
            .collect(),
    }
}

fn manifest_diagnostic_report(diagnostic: &AsicManifestDiagnostic) -> AsicManifestDiagnosticReport {
    AsicManifestDiagnosticReport {
        path: diagnostic.path.clone(),
        size: diagnostic.size,
        signature_references: diagnostic
            .signature_references
            .iter()
            .map(|reference| AsicManifestSignatureReferenceReport {
                uri: reference.uri.clone(),
                member_present: reference.member_present,
                member_kind: reference.member_kind.map(signature_member_kind),
            })
            .collect(),
        data_object_references: diagnostic
            .data_object_references
            .iter()
            .map(|reference| AsicManifestDataObjectReferenceReport {
                uri: reference.uri.clone(),
                mime_type: reference.mime_type.clone(),
                payload_present: reference.payload_present,
                sha256_digest: crate::hex::hex(&reference.sha256_digest),
                digest_matches: reference.digest_matches,
            })
            .collect(),
        blockers: diagnostic.blockers.iter().map(blocker_report).collect(),
    }
}

fn blocker_report(blocker: &AsicDiagnosticBlocker) -> AsicBlockerReport {
    AsicBlockerReport {
        id: blocker.id.as_str(),
        message: blocker.message.clone(),
        member_path: blocker.member_path.clone(),
    }
}

fn append_blocker_findings(report: &AsicProfileReport, findings: &mut Vec<AsicInspectionFinding>) {
    if report
        .blocker_details
        .iter()
        .any(|blocker| blocker.id == AsicDiagnosticBlockerId::XadesNotSupported)
    {
        findings.push(AsicInspectionFinding::warning(
            "xades_not_supported",
            "ASiC-XAdES was detected. Local technical validation does not establish signer trust, provider approval, qualification, revocation status, legal effect, or production ASiC/XAdES conformance.",
        ));
    }

    for blocker in &report.blocker_details {
        findings.push(AsicInspectionFinding::warning(
            blocker.id.as_str(),
            blocker.message.clone(),
        ));
    }
}

fn container_kind(value: AsicContainerKind) -> &'static str {
    match value {
        AsicContainerKind::AsicS => "asic_s",
        AsicContainerKind::AsicE => "asic_e",
        _ => "unknown",
    }
}

fn signature_profile(value: AsicSignatureProfile) -> &'static str {
    match value {
        AsicSignatureProfile::Cades => "cades",
        AsicSignatureProfile::Xades => "xades",
        AsicSignatureProfile::Mixed => "mixed",
        AsicSignatureProfile::Unsigned => "unsigned",
        _ => "unknown",
    }
}

fn bounded_profile(value: AsicBoundedProfile) -> &'static str {
    match value {
        AsicBoundedProfile::AsicSCadesSinglePayload => "asic_s_cades_single_payload",
        AsicBoundedProfile::AsicECadesSingleManifest => "asic_e_cades_single_manifest",
        _ => "unknown",
    }
}

fn profile_shape(value: AsicProfileShape) -> &'static str {
    match value {
        AsicProfileShape::AsicSCadesSinglePayload => "asic_s_cades_single_payload",
        AsicProfileShape::AsicSCadesUnsupported => "asic_s_cades_unsupported",
        AsicProfileShape::AsicSXades => "asic_s_xades",
        AsicProfileShape::AsicSMixed => "asic_s_mixed",
        AsicProfileShape::AsicSUnsigned => "asic_s_unsigned",
        AsicProfileShape::AsicECadesSingleManifest => "asic_e_cades_single_manifest",
        AsicProfileShape::AsicECadesUnsupported => "asic_e_cades_unsupported",
        AsicProfileShape::AsicEXades => "asic_e_xades",
        AsicProfileShape::AsicEMixed => "asic_e_mixed",
        AsicProfileShape::AsicEUnsigned => "asic_e_unsigned",
        _ => "unknown",
    }
}

fn signature_member_kind(value: AsicSignatureMemberKind) -> &'static str {
    match value {
        AsicSignatureMemberKind::Cades => "cades",
        AsicSignatureMemberKind::Xades => "xades",
        _ => "unknown",
    }
}

fn xades_level(value: XadesLevel) -> &'static str {
    match value {
        XadesLevel::B => "b",
        XadesLevel::T => "t",
        XadesLevel::LT => "lt",
        XadesLevel::LTA => "lta",
    }
}

fn signer_cert_subject(der: &[u8]) -> Option<String> {
    x509_cert::Certificate::from_der(der)
        .ok()
        .map(|cert| cert.tbs_certificate.subject.to_string())
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    crate::hex::hex(&digest)
}
