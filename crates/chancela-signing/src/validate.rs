//! Signature validation and reporting (SIG-24).
//!
//! Delegates the cryptographic and structural check to `chancela-cades` (detached CAdES) or
//! `chancela-pades` (PAdES over the embedded ByteRange), and folds in the evidentiary labelling and
//! trusted-list status recorded on the artifact. The EU DSS validation-sidecar cross-check (SIG-23)
//! is a documented phase-2 seam; this native path produces the report required at sealing time.

use time::OffsetDateTime;

use crate::{
    EvidentiaryLevel, SignatureArtifact, SignatureFormat, SigningError, TrustedListStatus,
};

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
}

/// Validate a produced [`SignatureArtifact`] and build its report (SIG-24).
///
/// For [`SignatureFormat::PAdES`] the artifact's [`SignatureArtifact::signature`] bytes are the
/// signed PDF and validation is self-contained (`content_digest` is ignored). For
/// [`SignatureFormat::CAdES`] the bytes are the detached CMS and the caller MUST supply the
/// `content_digest` the signature covers. Other formats are not yet supported (phase-2).
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
            })
        }
        other => Err(SigningError::UnsupportedFormat(other)),
    }
}
