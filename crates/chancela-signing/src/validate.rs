//! Signature validation and reporting (SIG-24).
//!
//! Delegates the cryptographic and structural check to `chancela-cades` (detached CAdES),
//! `chancela-pades` (PAdES over the embedded ByteRange), or the bounded ASiC-S/CAdES parser, and
//! folds in the evidentiary labelling and trusted-list status recorded on the artifact. The EU DSS
//! validation-sidecar cross-check (SIG-23) is a documented phase-2 seam; this native path produces
//! the report required at sealing time.

use time::OffsetDateTime;

use crate::{
    EvidentiaryLevel, SignatureArtifact, SignatureFormat, SigningError, TrustedListStatus,
};

/// Policy input for technical timestamp-trust validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampTrustPolicy {
    /// Accepted `TSTInfo.policy` OIDs in dotted notation. Empty means no configured/known policy
    /// OID is enforced by this layer.
    pub accepted_policy_oids: Vec<String>,
}

impl TimestampTrustPolicy {
    /// Build a policy that enforces one of the supplied `TSTInfo.policy` OIDs.
    pub fn require_one_of(
        accepted_policy_oids: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            accepted_policy_oids: accepted_policy_oids.into_iter().map(Into::into).collect(),
        }
    }
}

/// Technical timestamp-trust outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampTrustDecision {
    /// Token, policy, TSL/QTST match and offline certificate path all passed.
    Accepted,
    /// One or more technical checks failed. See
    /// [`TimestampTrustReport::failure_reasons`].
    Rejected,
}

/// QTST match evidence copied into the timestamp-trust report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampQtstMatchReport {
    pub provider_name: String,
    pub service_name: String,
    pub granted_and_effective: bool,
    pub trust_anchor_count: usize,
}

/// Technical trust report for an RFC 3161 signature timestamp.
///
/// This is deliberately a technical policy report. It records local cryptographic, path, policy
/// OID and TSL/QTST evidence; it does not make a legal qualification or probative-value claim.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TimestampTrustReport {
    pub decision: TimestampTrustDecision,
    pub timestamp_policy_oid: String,
    pub policy_oid_accepted: Option<bool>,
    pub tsa_certificate_embedded: bool,
    pub embedded_certificate_count: usize,
    pub trusted_list_status: TrustedListStatus,
    pub trusted_list_authenticated: bool,
    pub qtst_matches: Vec<TimestampQtstMatchReport>,
    pub trust_anchor_count: usize,
    pub certificate_path_valid: bool,
    pub certificate_path_anchor_index: Option<usize>,
    pub certificate_path_len: Option<usize>,
    pub failure_reasons: Vec<String>,
    pub scope_note: &'static str,
}

/// A signature-validation report (SIG-24).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignatureValidationReport {
    /// Whether the signature verified cryptographically over its content (always `true` on `Ok`).
    pub cryptographically_valid: bool,
    /// The signer's certificate, DER-encoded, as embedded in the signature.
    pub signer_cert_der: Vec<u8>,
    /// The `signing-time` attribute, if present.
    pub signing_time: Option<OffsetDateTime>,
    /// The trusted-list status recorded when the artifact was produced (SIG-11/23), if any.
    pub trusted_list_status: Option<TrustedListStatus>,
    /// Whether a qualified signature timestamp is present (PAdES-B-T, or a CAdES token attached as
    /// evidence) (SIG-22).
    pub has_signature_timestamp: bool,
    /// The evidentiary weight this artifact carries (SIG-01).
    pub evidentiary_level: EvidentiaryLevel,
    /// For PAdES, whether the ByteRange covers the whole file except the `/Contents` value (the
    /// well-formed shape). `None` for detached CAdES.
    pub covers_whole_file: Option<bool>,
    /// Embedded PAdES DSS/VRI evidence, if any. Empty for detached CAdES.
    pub dss: chancela_pades::DssReport,
    /// Technical local evidence marker: true only when a PAdES signature has B-T timestamp evidence
    /// and embedded DSS OCSP/CRL material. This is not a legal B-LT sufficiency claim.
    pub has_local_dss_revocation_evidence: bool,
}

/// Validate a produced [`SignatureArtifact`] and build its report (SIG-24).
///
/// For [`SignatureFormat::PAdES`] the artifact's [`SignatureArtifact::signature`] bytes are the
/// signed PDF and validation is self-contained (`content_digest` is ignored). For
/// [`SignatureFormat::CAdES`] the bytes are the detached CMS and the caller MUST supply the
/// `content_digest` the signature covers. For [`SignatureFormat::ASiC`] the bytes are a bounded
/// ASiC-S ZIP container and validation is self-contained; if `content_digest` is supplied, it is
/// cross-checked against the packaged payload digest. XAdES remains unsupported (phase-2).
pub fn validate_signature(
    artifact: &SignatureArtifact,
    content_digest: Option<&[u8; 32]>,
) -> Result<SignatureValidationReport, SigningError> {
    match artifact.format {
        SignatureFormat::PAdES => {
            let report = chancela_pades::validate_pdf_signature(&artifact.signature)
                .map_err(|e| SigningError::Pades(e.to_string()))?;
            Ok(SignatureValidationReport {
                cryptographically_valid: true,
                signer_cert_der: report.cades.signer_cert_der,
                signing_time: report.cades.signing_time,
                trusted_list_status: artifact.trusted_list_status,
                has_signature_timestamp: report.has_signature_timestamp,
                evidentiary_level: artifact.evidentiary_level,
                covers_whole_file: Some(report.covers_whole_file_except_contents),
                has_local_dss_revocation_evidence: report.has_signature_timestamp
                    && report.dss.has_revocation_evidence(),
                dss: report.dss,
            })
        }
        SignatureFormat::CAdES => {
            let content_digest = content_digest.ok_or(SigningError::FormatInputMismatch {
                format: SignatureFormat::CAdES,
            })?;
            let validation = chancela_cades::validate_cades_b(&artifact.signature, content_digest)
                .map_err(|e| SigningError::Cades(e.to_string()))?;
            Ok(SignatureValidationReport {
                cryptographically_valid: true,
                signer_cert_der: validation.signer_cert_der,
                signing_time: validation.signing_time,
                trusted_list_status: artifact.trusted_list_status,
                has_signature_timestamp: artifact.timestamp_token_der.is_some(),
                evidentiary_level: artifact.evidentiary_level,
                covers_whole_file: None,
                dss: chancela_pades::DssReport::default(),
                has_local_dss_revocation_evidence: false,
            })
        }
        SignatureFormat::ASiC => {
            let container = crate::asic::extract_asic_s_container(&artifact.signature)?;
            let packaged_digest = crate::asic::sha256_content_digest(&container.content);
            if let Some(expected) = content_digest {
                if expected != &packaged_digest {
                    return Err(SigningError::Asic(
                        "ASiC payload digest does not match the supplied content digest"
                            .to_string(),
                    ));
                }
            }

            let cades_artifact = SignatureArtifact {
                id: artifact.id,
                slot: artifact.slot,
                family: artifact.family,
                format: SignatureFormat::CAdES,
                profile: artifact.profile,
                evidentiary_level: artifact.evidentiary_level,
                signed_at: artifact.signed_at,
                signature: container.cades_signature_der,
                trusted_list_status: artifact.trusted_list_status,
                timestamp_token_der: artifact.timestamp_token_der.clone(),
            };
            validate_signature(&cades_artifact, Some(&packaged_digest))
        }
        other => Err(SigningError::UnsupportedFormat(other)),
    }
}

/// Validate technical timestamp trust from already-verified RFC 3161 output and QTST details.
///
/// The caller is expected to feed `timestamp` from `chancela-tsa::verify_response` or an
/// equivalent path that has already checked the token structure, imprint/nonce binding, signed
/// attributes and TSA CMS signature value. This function then combines the embedded TSA
/// certificate material, QTST match anchors from `chancela-tsl`, optional policy-OID enforcement
/// and the offline TSA certificate-path validator into one fail-closed report.
pub fn validate_timestamp_trust(
    timestamp: &chancela_tsa::Timestamp,
    qtst: &chancela_tsl::QtstMatchDetails,
    policy: &TimestampTrustPolicy,
) -> TimestampTrustReport {
    let mut failure_reasons = Vec::new();

    let policy_oid_accepted = if policy.accepted_policy_oids.is_empty() {
        None
    } else {
        let accepted = policy
            .accepted_policy_oids
            .iter()
            .any(|oid| oid == &timestamp.policy);
        if !accepted {
            failure_reasons.push(format!(
                "timestamp policy OID {} is not configured as accepted",
                timestamp.policy
            ));
        }
        Some(accepted)
    };

    let trusted_list_status = if qtst.authenticated {
        TrustedListStatus::from(qtst.status)
    } else {
        if qtst.status == chancela_tsl::QualifiedStatus::Granted {
            failure_reasons
                .push("TSL grant is unauthenticated and was downgraded to Unknown".to_owned());
        }
        TrustedListStatus::Unknown
    };

    if trusted_list_status != TrustedListStatus::Granted {
        failure_reasons.push(format!(
            "QTST trusted-list status is {trusted_list_status:?}, not Granted"
        ));
    }

    let mut certificate_path_valid = false;
    let mut certificate_path_anchor_index = None;
    let mut certificate_path_len = None;

    match timestamp.tsa_certificate_der.as_deref() {
        Some(tsa_cert) if trusted_list_status == TrustedListStatus::Granted => {
            if qtst.trust_anchor_ders.is_empty() {
                failure_reasons
                    .push("QTST match returned no authenticated trust anchors".to_owned());
            } else {
                match chancela_tsa::validate_tsa_certificate_path(
                    tsa_cert,
                    &timestamp.embedded_certificate_ders,
                    &qtst.trust_anchor_ders,
                    timestamp.gen_time,
                ) {
                    Ok(path) => {
                        certificate_path_valid = true;
                        certificate_path_anchor_index = Some(path.trust_anchor_index);
                        certificate_path_len = Some(path.path_der.len());
                    }
                    Err(err) => {
                        failure_reasons.push(format!("TSA certificate path failed: {err}"));
                    }
                }
            }
        }
        Some(_) => {}
        None => failure_reasons
            .push("timestamp token did not expose an embedded TSA signing certificate".to_owned()),
    }

    let qtst_matches = qtst
        .matches
        .iter()
        .map(|m| TimestampQtstMatchReport {
            provider_name: m.provider_name.clone(),
            service_name: m.service_name.clone(),
            granted_and_effective: m.granted_and_effective,
            trust_anchor_count: m.trust_anchor_ders.len(),
        })
        .collect();

    TimestampTrustReport {
        decision: if failure_reasons.is_empty() {
            TimestampTrustDecision::Accepted
        } else {
            TimestampTrustDecision::Rejected
        },
        timestamp_policy_oid: timestamp.policy.clone(),
        policy_oid_accepted,
        tsa_certificate_embedded: timestamp.tsa_certificate_der.is_some(),
        embedded_certificate_count: timestamp.embedded_certificate_ders.len(),
        trusted_list_status,
        trusted_list_authenticated: qtst.authenticated,
        qtst_matches,
        trust_anchor_count: qtst.trust_anchor_ders.len(),
        certificate_path_valid,
        certificate_path_anchor_index,
        certificate_path_len,
        failure_reasons,
        scope_note: "technical timestamp trust report only; no legal qualification claim",
    }
}
