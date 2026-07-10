//! Qualified Chave Móvel Digital signing endpoints (t57-S3): the async two-phase state machine
//! that turns a sealed act's unsigned PDF/A into a **qualified** CMD-signed PDF, its status/read
//! surface, and the `require_qualified_for_seal` enforcement semantics.
//!
//! ## Why two phases
//!
//! A CMD signature is interactive: the citizen receives an OTP by SMS *between* starting the
//! signature and confirming it. That round-trip cannot live inside one HTTP request, so signing is a
//! **distinct post-seal step** split across two requests (t57 ruling 1):
//!
//! ```text
//! [act SEALED, unsigned PDF/A persisted]                      (existing seal flow, unchanged)
//!        │  POST /v1/acts/{id}/signature/cmd/initiate  { phone, pin }
//!        ▼
//!   prepare_signature(sealed PDF) → cmd_initiate (GetCertificate → TSL gate → CCMovelSign;
//!   dispatches the OTP) → persist a PENDING session (no PIN) → { session_id, masked_phone }
//!        │  [citizen receives the SMS OTP]
//!        │  POST /v1/acts/{id}/signature/cmd/confirm   { session_id, otp }
//!        ▼
//!   cmd_confirm (ValidateOtp → CMS) → embed_signature → validate (SIG-24) → persist the SIGNED
//!   variant + a chained `document.signed` event → the act reaches finalizado-qualificado
//! ```
//!
//! ## Secret discipline (t57 ruling 4 / §6)
//!
//! The **PIN** (initiate) and **OTP** (confirm) are transient knowledge/possession factors: each is
//! read into a [`Zeroizing`] buffer, consumed by the single call that needs it, and dropped —
//! **never** persisted, logged, or echoed. The persisted [`PendingCmdSession`] carries only the
//! non-secret resumable handle (SCMD process id, the public account id, the signer certificate, the
//! ByteRange digest, the signing time). The F5 seam guarantees no secret enters that blob; a test
//! asserts it.
//!
//! ## Enforcement (t57 ruling 6 / deliverable D)
//!
//! `signing.require_qualified_for_seal` gates the **finalizado-qualificado STATUS**, not the seal.
//! Sealing always succeeds and always produces the unsigned PDF/A. With the setting on, an act stays
//! `aguarda_assinatura_qualificada` until a genuine qualified signature is present; with it off, a
//! sealed act is `finalizado` on the non-qualified path. No endpoint sets the qualified status
//! directly — it is *derived* from the presence of a validated `Qualified` signed variant, so it is
//! unbypassable.

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chancela_cmd::{CmdConfig, CmdEnv, HttpScmdTransport, ScmdClient, ScmdTransport};
use chancela_csc::rest::Authorization as CscAuthHeader;
use chancela_csc::{
    CscAuthorization, CscClient, CscConfig, CscError, CscRemoteSource, CscSecrets, CscTransport,
    HttpCscTransport,
};
use chancela_pades::{
    PreparedSignature, SignOptions, add_signature_timestamp, embed_signature, prepare_signature,
};
use chancela_signing::{
    CMD_PROVIDER_ID, CcSignedPdf, CmdInitiate, CmdRemoteSource, CmdSignSession, RemoteInitiate,
    RemoteSignSession, RemoteSigningSource, SignerProvider, SmartcardProvider,
    TimestampTrustDecision, TimestampTrustPolicy, TimestampTrustReport, TrustPolicy,
    TrustedListStatus, TslTrustPolicy, attach_pdf_dss, attach_pdf_revocation_evidence, cmd_confirm,
    cmd_initiate, sign_pdf_cc, sign_pdf_pades, validate_timestamp_trust,
};
use chancela_signing::{Pkcs12IdentitySelector, Pkcs12SigningSource, SoftCertificateError};
use chancela_smartcard::Pkcs11Token;
use chancela_store::{PendingCmdSession, StoredDocument, StoredSignedDocument};
use chancela_tsl::{FileTslSource, TslClient, TslError, TslSource};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroizing;

use chancela_authz::{Permission, Scope};
use chancela_core::ActId;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::actor::CurrentAttestor;
use crate::authz::{require_permission, scope_of_act};
use crate::error::ApiError;
use crate::settings::{RuntimeTsaProvider, RuntimeTslSource};

/// The signing family this module produces (v1 is CMD-only; t57 ruling 2).
const FAMILY_CMD: &str = "ChaveMovelDigital";
/// The signing family an external CSC-standard QTSP produces (t59 ruling 4:
/// `SigningFamily::QualifiedCertificate` + a separate `provider_id`, never a per-vendor family).
const FAMILY_QUALIFIED: &str = "QualifiedCertificate";
/// The evidentiary level a successful CMD signature carries (SIG-01).
const EVIDENTIARY_QUALIFIED: &str = "Qualified";
/// The family label for user-mediated official app/provider handoff imports. This is a technical
/// import marker, not a provider/trust assertion.
const FAMILY_OFFICIAL_HANDOFF: &str = "AutenticacaoGovOfficialHandoff";
/// Imported official handoff evidence is cryptographically screened but not TSL/qualified-validated.
const EVIDENTIARY_IMPORTED_OFFICIAL: &str = "ImportedOfficialHandoffTechnicalEvidence";
/// External signer invite uploads are stored as technical evidence only, never as legal validation.
const FAMILY_EXTERNAL_SIGNER_HANDOFF: &str = "ExternalSignerHandoff";
const EVIDENTIARY_EXTERNAL_SIGNED_PDF: &str = "ExternalSignedPdfTechnicalEvidence";
const EXTERNAL_SIGNED_PDF_NOTICE: &str = "Uploaded signed PDF technical evidence only; no legal validity, qualified-signature, or trust-list status is claimed.";
const FAMILY_LOCAL_PKCS12: &str = "LocalPkcs12SoftwareCertificate";
const EVIDENTIARY_ADVANCED_LOCAL: &str = "AdvancedLocalTechnicalEvidence";
const LOCAL_PKCS12_NOTICE: &str = "Local software-certificate PAdES technical evidence only; no qualified remote/CMD signature, trusted-list status, or legal qualification is claimed.";
/// The signed-PDF profile strings bound into the `document.signed` event.
const PADES_PROFILE_B_B: &str = "application/pdf; profile=PAdES-B-B";
const PADES_PROFILE_B_T: &str = "application/pdf; profile=PAdES-B-T";
const EVIDENCE_LEVEL_UNSIGNED: &str = "Unsigned";
const EVIDENCE_LEVEL_B_B: &str = "B-B";
const EVIDENCE_LEVEL_B_T: &str = "B-T";
const EVIDENCE_LEVEL_B_LT_LOCAL: &str = "B-LT-local";
const EVIDENCE_LEVEL_B_LTA_LOCAL: &str = "B-LTA-local";
const DSS_INSPECTION_NOT_APPLICABLE: &str = "not_applicable";
const DSS_INSPECTION_INSPECTED: &str = "inspected_from_signed_pdf";
const DSS_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const DSS_REVOCATION_NOT_APPLICABLE: &str = "not_applicable";
const DSS_REVOCATION_NOT_PRESENT: &str = "not_present";
const DSS_REVOCATION_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const DSS_REVOCATION_LOCAL_TECHNICAL_ONLY: &str = "present_local_technical_only";
const DSS_REVOCATION_PRESENT_WITHOUT_TIMESTAMP: &str = "present_without_signature_timestamp";
const PRODUCTION_B_LT_NOT_CLAIMED: &str = "not_claimed";
const TECHNICAL_EVIDENCE_ONLY: &str = "technical_evidence_only";
const DOC_TIMESTAMP_INSPECTION_INSPECTED: &str = "inspected_from_signed_pdf";
const DOC_TIMESTAMP_INSPECTION_UNAVAILABLE: &str = "inspection_unavailable";
const RENEWAL_POLICY_NOT_CONFIGURED: &str = "not_configured";
const RENEWAL_POLICY_MANUAL_REVIEW: &str = "manual_review";
const LOCAL_TECHNICAL_EVIDENCE_ONLY: &str = "local_technical_evidence_only";
const RENEWAL_PLAN_NOTICE: &str =
    "Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.";
const RENEWAL_PLAN_AVAILABLE: &str = "available";
const RENEWAL_PLAN_NOT_APPLICABLE: &str = "not_applicable";
const RENEWAL_PLAN_UNAVAILABLE: &str = "unavailable";
const RENEWAL_PLAN_ACTION_NONE: &str = "none";
const RENEWAL_PLAN_ACTION_MANUAL_REVIEW: &str = "manual_review";
/// Pending-session lifetime, aligned to the SCMD OTP validity window.
const SESSION_TTL_SECS: i64 = 5 * 60;
const EXTERNAL_INVITE_NOTICE: &str = "Acompanhamento de convite externo apenas; esta acao nao assina o documento nem conclui assinatura qualificada.";
const EXTERNAL_INVITE_WORKING_COPY_PATH: &str =
    "/v1/signature/external-invites/document/working-copy";
const EXTERNAL_INVITE_WORKING_COPY_KIND: &str = "working_copy_markdown";
const EXTERNAL_INVITE_WORKING_COPY_CONTENT_TYPE: &str = "text/markdown; charset=utf-8";
const EXTERNAL_INVITE_WORKING_COPY_NOTICE: &str = "Copia Markdown nao probatoria para revisao; nao e o PDF/A preservado, nao e um PDF assinado e nao conclui assinatura qualificada.";
/// Decoded signed-PDF import cap for the first official handoff slice.
pub(crate) const OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// HTTP envelope cap: enough for raw PDF bytes plus JSON/base64 overhead.
pub(crate) const OFFICIAL_SIGNATURE_IMPORT_ENVELOPE_BYTES: usize =
    OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES * 4 / 3 + 64 * 1024;
/// Decoded PKCS#12/PFX cap for local software-certificate signing. The PFX is used transiently and
/// is never persisted.
pub(crate) const LOCAL_PKCS12_SIGN_MAX_BYTES: usize = 3 * 1024 * 1024;
/// HTTP envelope cap: enough for encrypted PFX bytes plus JSON/base64 overhead.
pub(crate) const LOCAL_PKCS12_SIGN_ENVELOPE_BYTES: usize =
    LOCAL_PKCS12_SIGN_MAX_BYTES * 4 / 3 + 64 * 1024;
/// DSS attach bodies carry small DER evidence arrays as base64 strings.
pub(crate) const DSS_ATTACH_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

// --- request / response DTOs ------------------------------------------------------------------

/// Body of `POST /v1/acts/{id}/signature/cmd/initiate`.
#[derive(Deserialize)]
pub struct CmdInitiateRequest {
    /// The citizen mobile number in SCMD format (`+351 XXXXXXXXX`).
    pub phone: String,
    /// The CMD signature PIN (knowledge factor). **Transient — consumed, never persisted/logged.**
    pub pin: String,
    /// The capacity in which the signer acts (optional, informational).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful initiate — **carries no secret** (no PIN, no OTP, no process id).
#[derive(Serialize)]
pub struct CmdInitiateResponse {
    /// The opaque pending-session id to submit with the OTP at confirm.
    pub session_id: String,
    /// The citizen phone with the middle digits masked (for the UI only).
    pub masked_phone: String,
    /// Always `"otp_pending"` here (the OTP has been dispatched to the device).
    pub status: &'static str,
    /// When the pending session expires (RFC 3339).
    pub expires_at: String,
    /// The family being produced (`ChaveMovelDigital`).
    pub family: &'static str,
    /// The evidentiary level the produced signature will carry (`Qualified`).
    pub evidentiary_level: &'static str,
}

/// Body of `POST /v1/acts/{id}/signature/cmd/confirm`.
#[derive(Deserialize)]
pub struct CmdConfirmRequest {
    /// The pending-session id returned by initiate.
    pub session_id: String,
    /// The SMS OTP (possession factor). **Transient — consumed, never persisted/logged.**
    pub otp: String,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful confirm.
#[derive(Serialize)]
pub struct CmdConfirmResponse {
    /// The signed document's source (unsigned) document id.
    pub document_id: String,
    /// The owning act id.
    pub act_id: String,
    /// The family (`ChaveMovelDigital`).
    pub family: &'static str,
    /// The evidentiary level (`Qualified`).
    pub evidentiary_level: &'static str,
    /// The signer issuer's trusted-list status at signing time, if a policy was consulted.
    pub trusted_list_status: Option<String>,
    /// When the signature completed (RFC 3339).
    pub signed_at: String,
    /// Lowercase-hex sha-256 of the signed PDF bytes.
    pub signed_pdf_digest: String,
    /// Whether an RFC 3161 signature timestamp is present (B-T); always `false` for B-B.
    pub timestamp_token: bool,
    /// The derived finalization status (`finalizado_qualificado`).
    pub finalization: &'static str,
}

/// `GET /v1/acts/{id}/signature` — the act's signature status view.
#[derive(Serialize)]
pub struct SignatureStatusView {
    /// `"unsigned"` | `"pending"` | `"signed"`.
    pub status: &'static str,
    /// The derived finalization status (see module docs): `rascunho` | `finalizado` |
    /// `aguarda_assinatura_qualificada` | `finalizado_qualificado`.
    pub finalization: &'static str,
    /// Whether `require_qualified_for_seal` is on (so the UI can explain the pending state).
    pub require_qualified_for_seal: bool,
    /// Signed-variant detail, present only when `status == "signed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<SignedInfo>,
    /// Pending-session detail, present only when `status == "pending"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingInfo>,
    /// Technical signature-evidence status. This reports only the evidence profile observed by
    /// Chancela; it is not a legal qualification or conformance certification.
    pub evidence: SignatureEvidenceStatus,
}

/// The signed-variant detail surfaced on the status view.
#[derive(Serialize)]
pub struct SignedInfo {
    pub family: String,
    pub evidentiary_level: String,
    pub trusted_list_status: Option<String>,
    pub signer_cert_subject: Option<String>,
    pub signing_time: String,
    pub signed_at: String,
    pub signed_pdf_digest: String,
    pub timestamp_token: bool,
    pub download: String,
}

/// The pending-session detail surfaced on the status view (no secrets).
#[derive(Serialize)]
pub struct PendingInfo {
    pub session_id: String,
    pub masked_phone: String,
    pub expires_at: String,
}

/// Technical evidence profile observed for the signed act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureEvidenceStatus {
    /// `"Unsigned"`, `"B-B"`, `"B-T"`, `"B-LT-local"`, or `"B-LTA-local"`. The local markers mean
    /// Chancela observed embedded technical evidence; they are not production/legal LTV claims.
    pub current_level: &'static str,
    /// Whether an RFC 3161 signature timestamp token is present.
    pub timestamp_evidence_present: bool,
    /// Whether embedded DSS OCSP/CRL validation material is present in the signed artifact.
    pub dss_revocation_evidence_present: bool,
    /// Local DSS/revocation status. A present value is technical evidence only, not legal B-LT.
    pub dss_revocation_evidence_status: &'static str,
    /// Detailed embedded DSS/VRI counts and hashes read from the signed PDF.
    pub dss: DssEvidenceStatus,
    /// Detailed embedded `/DocTimeStamp` report read from the signed PDF.
    pub doc_timestamp: DocTimeStampEvidenceStatus,
    /// True only for the technical B-T + DSS revocation combination that resembles B-LT evidence.
    pub local_b_lt_style_evidence_present: bool,
    /// Production/legal B-LT is not claimed by this local DSS reporting surface.
    pub production_b_lt_status: &'static str,
    /// This status is derived only from embedded PDF bytes; no live OCSP/CRL fetch is performed.
    pub live_revocation_fetching: bool,
    /// Guardrail for consumers that might otherwise infer a legal/conformance conclusion.
    pub legal_b_lt_claimed: bool,
    /// Guardrail for consumers that might otherwise infer a legal/conformance B-LTA conclusion.
    pub legal_b_lta_claimed: bool,
    /// Archive timestamp renewal policy. No automatic renewal is configured in this API surface.
    pub renewal_policy: RenewalPolicyEvidenceStatus,
    /// Local technical evidence continuity plan from embedded PAdES evidence. This is not a
    /// B-LT/B-LTA profile claim, legal LTV claim, or production renewal schedule.
    pub local_technical_renewal_plan: LocalTechnicalRenewalPlanEvidenceStatus,
    /// Explicit long-term evidence milestones and gaps. Local B-LT/B-LTA markers are technical
    /// evidence only; production/legal LTV remains not claimed.
    pub long_term_status: Vec<LongTermEvidenceStatus>,
    /// Technical timestamp-trust diagnostics from the RFC 3161 token and authenticated QTST
    /// evidence, when the full validator inputs were persisted for this signed artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_trust: Option<TimestampTrustEvidenceStatus>,
    /// Scope marker for consumers: these fields describe technical evidence only.
    pub status_scope: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampTrustEvidenceStatus {
    /// `"accepted"` or `"rejected"` from technical timestamp-trust validation.
    pub decision: String,
    /// `TSTInfo.policy` OID observed in the timestamp token.
    pub policy_oid: String,
    /// Whether the policy OID matched the local accepted-policy set; `None` means no local policy
    /// OID allow-list was configured.
    pub policy_oid_accepted: Option<bool>,
    /// Whether the timestamp token exposed the TSA signing certificate.
    pub tsa_certificate_embedded: bool,
    pub embedded_certificate_count: usize,
    /// Trusted-list/QTST status after unauthenticated granted statuses are downgraded.
    pub qtst_status: String,
    /// Whether the QTST result came from an authenticated trusted list.
    pub qtst_authenticated: bool,
    pub qtst_matches: Vec<TimestampQtstMatchEvidenceStatus>,
    pub trust_anchor_count: usize,
    pub certificate_path_valid: bool,
    pub certificate_path_anchor_index: Option<usize>,
    pub certificate_path_len: Option<usize>,
    pub failure_reasons: Vec<String>,
    pub status_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampQtstMatchEvidenceStatus {
    pub provider_name: String,
    pub service_name: String,
    pub granted_and_effective: bool,
    pub trust_anchor_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DssEvidenceStatus {
    pub present: bool,
    pub vri_count: usize,
    pub certificate_count: usize,
    pub ocsp_count: usize,
    pub crl_count: usize,
    pub certificate_sha256: Vec<String>,
    pub ocsp_sha256: Vec<String>,
    pub crl_sha256: Vec<String>,
    pub revocation_evidence_present: bool,
    pub inspection_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocTimeStampEvidenceStatus {
    pub present: bool,
    pub count: usize,
    pub token_sha256: Vec<String>,
    pub validations: Vec<DocTimeStampValidationEvidenceStatus>,
    pub all_imprints_valid: bool,
    pub inspection_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DocTimeStampValidationEvidenceStatus {
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
pub struct RenewalPolicyEvidenceStatus {
    pub status: &'static str,
    pub action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalTechnicalRenewalPlanEvidenceStatus {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LongTermEvidenceStatus {
    NotConfigured,
    Timestamped,
    LtLocalTechnicalEvidence,
    LtLocalTechnicalEvidencePartial,
    LtProductionNotClaimed,
    LtNotImplemented,
    LtaLocalTechnicalEvidence,
    LtaLocalTechnicalEvidencePartial,
    LtaNotImplemented,
}

// --- official Autenticação.gov handoff import --------------------------------------------------

/// JSON envelope accepted by `POST /v1/acts/{id}/signature/official/import`.
///
/// The only artifact input is the signed PDF bytes. Optional `provider` / `source` / `filename`
/// values are client-declared trace context only; they are never used as authority for family,
/// trust-list status, or qualified/legal completion. Unknown fields are denied so callers cannot
/// smuggle secret factors (`pin`, `otp`, `can`, credentials, activation codes, passphrases, tokens).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialSignatureImportRequest {
    #[serde(
        alias = "signed_pdf",
        alias = "signed_pdf_base64",
        alias = "pdf_base64",
        alias = "bytes_base64",
        alias = "data_base64",
        alias = "base64"
    )]
    pub content_base64: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug)]
struct OfficialSignatureImportCandidate {
    signed_pdf_bytes: Vec<u8>,
    provider: Option<String>,
    source: Option<String>,
    filename: Option<String>,
    actor: Option<String>,
}

impl OfficialSignatureImportCandidate {
    fn has_client_metadata(&self) -> bool {
        self.provider.is_some() || self.source.is_some() || self.filename.is_some()
    }
}

/// Response for a successful official handoff import. This deliberately reports technical import
/// evidence only; qualified/legal completion is not claimed by this slice.
#[derive(Serialize)]
pub struct OfficialSignatureImportResponse {
    pub document_id: String,
    pub act_id: String,
    pub family: &'static str,
    pub evidentiary_level: &'static str,
    pub trusted_list_status: Option<String>,
    pub legal_validation: OfficialSignatureLegalValidation,
    pub signing_time: String,
    pub signed_at: String,
    pub signed_pdf_digest: String,
    pub timestamp_token: bool,
    pub finalization: &'static str,
    pub qualification_claimed: bool,
    pub client_metadata_authoritative: bool,
}

/// Explicit legal-validation boundary for official handoff imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfficialSignatureLegalValidation {
    pub pades_valid: bool,
    pub byte_range_covers_whole_file: bool,
    pub sealed_pdf_prefix_match: bool,
    pub trust_validation: &'static str,
    pub trust_validation_performed: bool,
    pub qualified_status_claimed: bool,
    pub legal_status_claimed: bool,
}

// --- local PKCS#12 software-certificate signing -----------------------------------------------

/// JSON envelope accepted by `POST /v1/acts/{id}/signature/local/pkcs12/sign`.
///
/// This is an advanced local-signing import flow: the encrypted PKCS#12 bytes and passphrase are
/// accepted only for this request, loaded into a [`Pkcs12SigningSource`], used to sign the sealed
/// PDF, then dropped. No PFX bytes, passphrase, or decrypted private key material are persisted or
/// copied into the audit event.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPkcs12SignRequest {
    #[serde(alias = "pkcs12", alias = "pfx_base64", alias = "pkcs12_der_base64")]
    pub pkcs12_base64: String,
    pub passphrase: String,
    #[serde(default)]
    pub friendly_name: Option<String>,
    /// The capacity in which the signer acts (optional, informational).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Actor override for attribution.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful local PKCS#12 software-certificate signature. This is deliberately
/// labelled as advanced local technical evidence, not a qualified remote/CMD signature.
#[derive(Serialize)]
pub struct LocalPkcs12SignResponse {
    pub document_id: String,
    pub act_id: String,
    pub family: &'static str,
    pub evidentiary_level: &'static str,
    pub trusted_list_status: Option<String>,
    pub signing_time: String,
    pub signed_at: String,
    pub signed_pdf_digest: String,
    pub signer_cert_subject: Option<String>,
    pub signer_cert_sha256: String,
    pub certificate_chain_count: usize,
    pub timestamp_token: bool,
    pub finalization: &'static str,
    pub qualification_claimed: bool,
    pub legal_status_claimed: bool,
    pub status_scope: &'static str,
    pub notice: &'static str,
}

// --- external signer invitations --------------------------------------------------------------

/// Body of `POST /v1/acts/{id}/signature/external-invites`.
#[derive(Deserialize)]
pub struct CreateExternalSignerInviteRequest {
    pub recipient_name: String,
    pub recipient_email: String,
    #[serde(default)]
    pub provider_hint: Option<String>,
    /// RFC 3339 timestamp after which the invitation is expired.
    pub expires_at: String,
    /// Why this person is being asked to sign. Informational only; this endpoint does not complete a
    /// legal remote signature.
    pub purpose: String,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Invitation lifecycle status. This is invitation/envelope state, not a completed-signature claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSignerInviteStatus {
    Pending,
    Accepted,
    Declined,
    Expired,
    Revoked,
}

/// External signer's envelope response. This is acknowledgement/tracking state; an accept can carry
/// a signed PDF artifact as technical evidence, but it is not a qualified-signature completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSignerInviteDecision {
    Accept,
    Decline,
}

/// The stored invite record. It intentionally does not contain the plaintext invite token: only a
/// SHA-256 hash and a short display hint are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalSignerInviteRecord {
    pub id: Uuid,
    pub act_id: ActId,
    pub recipient_name: String,
    pub recipient_email: String,
    pub provider_hint: Option<String>,
    pub purpose: String,
    pub token_sha256: String,
    pub token_hint: String,
    pub created_at: OffsetDateTime,
    pub created_by: String,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_by: Option<String>,
    pub response: Option<ExternalSignerInviteDecision>,
    pub responded_at: Option<OffsetDateTime>,
}

impl ExternalSignerInviteRecord {
    #[must_use]
    pub fn status_at(&self, now: OffsetDateTime) -> ExternalSignerInviteStatus {
        if self.revoked_at.is_some() {
            ExternalSignerInviteStatus::Revoked
        } else if let Some(response) = self.response {
            match response {
                ExternalSignerInviteDecision::Accept => ExternalSignerInviteStatus::Accepted,
                ExternalSignerInviteDecision::Decline => ExternalSignerInviteStatus::Declined,
            }
        } else if now >= self.expires_at {
            ExternalSignerInviteStatus::Expired
        } else {
            ExternalSignerInviteStatus::Pending
        }
    }
}

/// Public invite view. No token secret or token hash is serialized.
#[derive(Serialize)]
pub struct ExternalSignerInviteView {
    pub id: String,
    pub act_id: String,
    pub recipient_name: String,
    pub recipient_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
    pub purpose: String,
    pub status: ExternalSignerInviteStatus,
    pub workflow: &'static str,
    pub token_hint: String,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responded_at: Option<String>,
}

impl ExternalSignerInviteView {
    fn from_record(record: &ExternalSignerInviteRecord, now: OffsetDateTime) -> Self {
        ExternalSignerInviteView {
            id: record.id.to_string(),
            act_id: record.act_id.to_string(),
            recipient_name: record.recipient_name.clone(),
            recipient_email: record.recipient_email.clone(),
            provider_hint: record.provider_hint.clone(),
            purpose: record.purpose.clone(),
            status: record.status_at(now),
            workflow: "tracking_only",
            token_hint: record.token_hint.clone(),
            created_at: rfc3339(record.created_at),
            created_by: record.created_by.clone(),
            expires_at: rfc3339(record.expires_at),
            revoked_at: record.revoked_at.map(rfc3339),
            revoked_by: record.revoked_by.clone(),
            responded_at: record.responded_at.map(rfc3339),
        }
    }
}

/// Create response. The plaintext token is returned exactly once here and is never listed.
#[derive(Serialize)]
pub struct CreateExternalSignerInviteResponse {
    pub invite: ExternalSignerInviteView,
    pub token: String,
}

/// Body of the unauthenticated invite lookup endpoint. The token is accepted only in the JSON body,
/// never echoed, and never placed in an API path.
#[derive(Deserialize)]
pub struct ExternalSignerInviteTokenRequest {
    pub token: String,
}

/// Body of the unauthenticated invite response endpoint.
#[derive(Deserialize)]
pub struct ExternalSignerInviteRespondRequest {
    pub token: String,
    pub decision: ExternalSignerInviteDecision,
    #[serde(
        default,
        alias = "signed_pdf",
        alias = "signed_pdf_base64",
        alias = "pdf_base64",
        alias = "bytes_base64",
        alias = "data_base64",
        alias = "base64"
    )]
    pub signed_pdf_base64: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

/// Safe act metadata for a token holder. No document bytes or canonical PDF URL are exposed here.
#[derive(Clone, Serialize)]
pub struct ExternalSignerInviteActPublicView {
    pub id: String,
    pub title: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ata_number: Option<u64>,
    pub entity_name: String,
    pub book_kind: String,
}

/// Public non-canonical artifact descriptor for a token holder.
#[derive(Clone, Serialize)]
pub struct ExternalSignerInviteArtifactPublicView {
    pub kind: &'static str,
    pub method: &'static str,
    pub path: &'static str,
    pub content_type: &'static str,
    pub filename: String,
    pub notice: &'static str,
}

/// Safe sealed-document metadata for a token holder. No PDF bytes or canonical download URL.
#[derive(Clone, Serialize)]
pub struct ExternalSignerInviteDocumentPublicView {
    pub id: String,
    pub template_id: String,
    pub profile: String,
    pub pdf_digest: String,
    pub artifact: ExternalSignerInviteArtifactPublicView,
}

impl ExternalSignerInviteDocumentPublicView {
    fn from_document(act_id: ActId, doc: &StoredDocument) -> Self {
        Self {
            id: doc.id.clone(),
            template_id: doc.template_id.clone(),
            profile: doc.profile.clone(),
            pdf_digest: doc.pdf_digest.clone(),
            artifact: ExternalSignerInviteArtifactPublicView {
                kind: EXTERNAL_INVITE_WORKING_COPY_KIND,
                method: "POST",
                path: EXTERNAL_INVITE_WORKING_COPY_PATH,
                content_type: EXTERNAL_INVITE_WORKING_COPY_CONTENT_TYPE,
                filename: format!("act-{}-external-working-copy.md", act_id),
                notice: EXTERNAL_INVITE_WORKING_COPY_NOTICE,
            },
        }
    }
}

/// Public token-holder view. This is a tracking envelope only; it never claims that a legal or
/// qualified signature has been completed.
#[derive(Serialize)]
pub struct ExternalSignerInvitePublicView {
    pub invite_id: String,
    pub act: ExternalSignerInviteActPublicView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<ExternalSignerInviteDocumentPublicView>,
    pub recipient_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_hint: Option<String>,
    pub purpose: String,
    pub status: ExternalSignerInviteStatus,
    pub workflow: &'static str,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responded_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_artifact: Option<ExternalSignerInviteSignedArtifactPublicView>,
    pub notice: &'static str,
}

/// Signed artifact status surfaced to a token holder. This is technical evidence only.
#[derive(Serialize)]
pub struct ExternalSignerInviteSignedArtifactPublicView {
    pub family: String,
    pub evidentiary_level: String,
    pub signed_pdf_digest: String,
    pub timestamp_token: bool,
    pub status_scope: &'static str,
    pub qualification_claimed: bool,
    pub legal_status_claimed: bool,
    pub notice: &'static str,
}

/// `POST /v1/acts/{id}/signature/external-invites` — create an envelope-tracking invitation for an
/// external signer. This does not contact a provider and does not complete any signature.
pub async fn create_external_signer_invite(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CreateExternalSignerInviteRequest>,
) -> Result<(StatusCode, Json<CreateExternalSignerInviteResponse>), ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor_name = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let audit_scope = sealed_act_audit_scope(&state, act_id).await?;

    let recipient_name = required_trimmed(req.recipient_name, "recipient_name")?;
    let recipient_email = required_trimmed(req.recipient_email, "recipient_email")?;
    if !looks_like_email(&recipient_email) {
        return Err(ApiError::Unprocessable(
            "recipient_email must look like an email address".to_owned(),
        ));
    }
    let provider_hint = optional_trimmed(req.provider_hint);
    let purpose = required_trimmed(req.purpose, "purpose")?;
    let expires_at = parse_rfc3339(&req.expires_at, "expires_at")?;
    let now = OffsetDateTime::now_utc();
    if expires_at <= now {
        return Err(ApiError::Unprocessable(
            "expires_at must be in the future".to_owned(),
        ));
    }

    let token = generate_invite_token();
    let record = ExternalSignerInviteRecord {
        id: Uuid::new_v4(),
        act_id,
        recipient_name,
        recipient_email,
        provider_hint,
        purpose,
        token_sha256: sha256_hex(token.as_bytes()),
        token_hint: redact_invite_token(&token),
        created_at: now,
        created_by: actor_name.clone(),
        expires_at,
        revoked_at: None,
        revoked_by: None,
        response: None,
        responded_at: None,
    };
    let view = ExternalSignerInviteView::from_record(&record, now);
    record_external_invite_event(
        &state,
        &actor_name,
        &attestor,
        &audit_scope,
        "signature.external_invite.created",
        &view,
    )
    .await?;

    state
        .external_signer_invites
        .write()
        .await
        .insert(record.id, record);

    Ok((
        StatusCode::CREATED,
        Json(CreateExternalSignerInviteResponse {
            invite: view,
            token,
        }),
    ))
}

/// `GET /v1/acts/{id}/signature/external-invites` — list invite records for an act. The plaintext
/// token and token hash are never included.
pub async fn list_external_signer_invites(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<Vec<ExternalSignerInviteView>>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    ensure_act_exists(&state, act_id).await?;

    let now = OffsetDateTime::now_utc();
    let mut views: Vec<_> = state
        .external_signer_invites
        .read()
        .await
        .values()
        .filter(|record| record.act_id == act_id)
        .map(|record| ExternalSignerInviteView::from_record(record, now))
        .collect();
    views.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    Ok(Json(views))
}

/// `POST /v1/acts/{id}/signature/external-invites/{invite_id}/revoke` — revoke a tracked invite.
/// The record is retained and listed as revoked.
pub async fn revoke_external_signer_invite(
    State(state): State<AppState>,
    Path((id, invite_id)): Path<(Uuid, Uuid)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
) -> Result<Json<ExternalSignerInviteView>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let audit_scope = act_audit_scope(&state, act_id).await?;
    let actor_name = actor.resolve("api");
    let now = OffsetDateTime::now_utc();

    let mut record = {
        let invites = state.external_signer_invites.read().await;
        let record = invites.get(&invite_id).ok_or(ApiError::NotFound)?;
        if record.act_id != act_id {
            return Err(ApiError::NotFound);
        }
        record.clone()
    };
    if record.revoked_at.is_none() {
        record.revoked_at = Some(now);
        record.revoked_by = Some(actor_name.clone());
    }
    let view = ExternalSignerInviteView::from_record(&record, now);
    record_external_invite_event(
        &state,
        &actor_name,
        &attestor,
        &audit_scope,
        "signature.external_invite.revoked",
        &view,
    )
    .await?;

    state
        .external_signer_invites
        .write()
        .await
        .insert(invite_id, record);
    Ok(Json(view))
}

/// `POST /v1/signature/external-invites/lookup` — unauthenticated token lookup for the external
/// signer landing page. It returns only redacted envelope/act metadata and only while the token is
/// valid, unexpired, and not revoked.
pub async fn lookup_external_signer_invite(
    State(state): State<AppState>,
    Json(req): Json<ExternalSignerInviteTokenRequest>,
) -> Result<Json<ExternalSignerInvitePublicView>, ApiError> {
    let record = find_live_external_invite_by_token(&state, req.token).await?;
    Ok(Json(public_external_invite_view(&state, &record).await?))
}

/// `POST /v1/signature/external-invites/document/working-copy` — unauthenticated, token-gated
/// non-evidentiary Markdown preview/download for a live external invite. The token stays in the JSON
/// body; the raw canonical PDF/A and signed PDF are never exposed through this public surface.
pub async fn download_external_signer_invite_working_copy(
    State(state): State<AppState>,
    Json(req): Json<ExternalSignerInviteTokenRequest>,
) -> Result<Response, ApiError> {
    let record = find_live_external_invite_by_token(&state, req.token).await?;
    let context = external_invite_safe_context(&state, &record).await?;
    let document = context.document.ok_or(ApiError::NotFound)?;
    let body = external_invite_working_copy_markdown(&record, &context.act, &document);

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            EXTERNAL_INVITE_WORKING_COPY_CONTENT_TYPE,
        )
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", document.artifact.filename),
        )
        .body(Body::from(body))
        .map_err(|e| {
            ApiError::Internal(format!(
                "failed to build external invite working-copy response: {e}"
            ))
        })
}

/// `POST /v1/signature/external-invites/respond` — unauthenticated accept/decline acknowledgement
/// for a valid external invite token. An accept may also upload a signed PDF artifact, which is
/// stored as technical evidence only; it does not complete qualified signing or claim legal status.
pub async fn respond_external_signer_invite(
    State(state): State<AppState>,
    attestor: CurrentAttestor,
    Json(req): Json<ExternalSignerInviteRespondRequest>,
) -> Result<Json<ExternalSignerInvitePublicView>, ApiError> {
    let upload =
        signed_pdf_upload_from_invite_response(req.decision, req.signed_pdf_base64, req.filename)?;
    let mut record = find_live_external_invite_by_token(&state, req.token).await?;
    let _ = external_invite_safe_context(&state, &record).await?;
    if let Some(existing) = record.response {
        if existing != req.decision {
            return Err(ApiError::Conflict(
                "este convite externo já foi respondido com outra decisão".to_owned(),
            ));
        }
        if let Some(upload) = upload {
            store_external_invite_signed_pdf_evidence(&state, &attestor, &record, upload).await?;
        }
        return Ok(Json(public_external_invite_view(&state, &record).await?));
    }

    let now = OffsetDateTime::now_utc();
    if let Some(upload) = &upload {
        prepare_external_signed_pdf_evidence(
            &state,
            record.act_id,
            upload.signed_pdf_bytes.clone(),
        )
        .await?;
    }
    record.response = Some(req.decision);
    record.responded_at = Some(now);
    let audit_scope = act_audit_scope(&state, record.act_id).await?;
    let actor_name = format!("external-signer:{}", record.id);
    let view = ExternalSignerInviteView::from_record(&record, now);
    let kind = match req.decision {
        ExternalSignerInviteDecision::Accept => "signature.external_invite.accepted",
        ExternalSignerInviteDecision::Decline => "signature.external_invite.declined",
    };
    record_external_invite_event(&state, &actor_name, &attestor, &audit_scope, kind, &view).await?;

    state
        .external_signer_invites
        .write()
        .await
        .insert(record.id, record.clone());

    if let Some(upload) = upload {
        store_external_invite_signed_pdf_evidence(&state, &attestor, &record, upload).await?;
    }

    Ok(Json(public_external_invite_view(&state, &record).await?))
}

// --- initiate ---------------------------------------------------------------------------------

/// `POST /v1/acts/{id}/signature/cmd/initiate` — phase 1 of the two-phase CMD signature.
///
/// Loads the act's sealed unsigned PDF/A, prepares the PAdES incremental update, runs
/// `GetCertificate` → the trusted-list gate → `CCMovelSign` (which dispatches the OTP), persists the
/// non-secret pending session, and returns `{ session_id, masked_phone, … }`. The PIN is transient.
pub async fn initiate_cmd_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    Json(req): Json<CmdInitiateRequest>,
) -> Result<Json<CmdInitiateResponse>, ApiError> {
    // RBAC (t64-E3): a qualified signature is `signing.perform` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    // Hold the PIN transiently: consumed by cmd_initiate, then zeroized on drop. Never stored/logged.
    let pin = Zeroizing::new(req.pin);
    let phone = req.phone.trim().to_string();
    if !looks_like_scmd_phone(&phone) {
        return Err(ApiError::Unprocessable(
            "número de telemóvel inválido para a Chave Móvel Digital (formato +351 XXXXXXXXX)"
                .to_owned(),
        ));
    }
    let act_id = ActId(id);

    // Resolve the act's sealed unsigned document, refusing a not-sealed act. Read locks only
    // (books → acts, plus entity presence); the durable write happens at confirm.
    {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        if act.ata_number.is_none() {
            return Err(ApiError::Conflict(
                "o ato ainda não foi selado; a assinatura qualificada é um passo posterior ao selo"
                    .to_owned(),
            ));
        }
    }
    let unsigned = crate::documents::load_document(&state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    // Reject a second signature over an already-signed act (single qualified artifact per act).
    if load_signed(&state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem uma assinatura qualificada".to_owned(),
        ));
    }

    let cmd_cfg = resolve_cmd_config(&state).await?;
    let tsl_source = configured_tsl_source(&state).await?;

    // Prepare the PAdES incremental update: compute the ByteRange digest to sign. A fixed signing
    // time (whole seconds) is carried unchanged into confirm (determinism, F5).
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let reason = match req
        .capacity
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(capacity) => format!("Assinatura qualificada da ata ({capacity})"),
        None => "Assinatura qualificada da ata".to_owned(),
    };
    let opts = SignOptions {
        field_name: Some("Assinatura".to_owned()),
        signing_time: Some(pdf_time(signing_time)),
        reason: Some(reason),
        location: None,
        contact_info: None,
    };
    let prepared = prepare_signature(&unsigned.pdf_bytes, &opts).map_err(|e| {
        // A sealed PDF/A that the two-phase PAdES cannot prepare (e.g. xref-stream form) is a
        // client-visible precondition, not a 500.
        ApiError::Unprocessable(format!(
            "não foi possível preparar o PDF para assinatura: {e}"
        ))
    })?;

    let doc_name = format!("ata-{}.pdf", act_id);
    let session = run_cmd_initiate(
        &state,
        &cmd_cfg,
        tsl_source,
        &phone,
        &pin,
        &doc_name,
        signing_time,
        &prepared,
    )
    .await?;
    // PIN no longer needed — drop it explicitly (also zeroizes) before persisting anything.
    drop(pin);

    // Persist the non-secret pending session (durable + in-memory) so confirm survives across the
    // two requests and a restart. NEVER writes a PIN/OTP.
    let session_id = Uuid::new_v4().to_string();
    let expires_at = signing_time + time::Duration::seconds(SESSION_TTL_SECS);
    let masked_phone = mask_phone(&phone);
    let pending = PendingCmdSession {
        session_id: session_id.clone(),
        act_id,
        actor,
        status: "otp_pending".to_owned(),
        masked_phone: masked_phone.clone(),
        doc_name,
        session_json: serde_json::to_string(&session)?,
        prepared_json: serde_json::to_string(&prepared)?,
        created_at: signing_time,
        expires_at,
    };
    if let Some(store) = &state.store {
        store
            .persist(|tx| tx.upsert_pending_cmd_session(&pending))
            .map_err(|e| ApiError::Internal(format!("failed to persist pending session: {e}")))?;
    }
    state
        .pending_signatures
        .write()
        .await
        .insert(session_id.clone(), pending);

    Ok(Json(CmdInitiateResponse {
        session_id,
        masked_phone,
        status: "otp_pending",
        expires_at: rfc3339(expires_at),
        family: FAMILY_CMD,
        evidentiary_level: EVIDENTIARY_QUALIFIED,
    }))
}

// --- confirm ----------------------------------------------------------------------------------

/// `POST /v1/acts/{id}/signature/cmd/confirm` — phase 2 of the two-phase CMD signature.
///
/// Loads the pending session (gated to the initiating actor), runs `ValidateOtp` → CMS →
/// `embed_signature` → validation (SIG-24), then persists the SIGNED variant + a chained
/// `document.signed` event and consumes the session — all in one durable commit. The OTP is transient.
pub async fn confirm_cmd_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CmdConfirmRequest>,
) -> Result<Json<CmdConfirmResponse>, ApiError> {
    // RBAC (t64-E3): confirming a qualified signature is `signing.perform` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let otp = Zeroizing::new(req.otp);
    let act_id = ActId(id);

    let pending = load_pending(&state, &req.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Session safety: single-use, act-scoped, gated to the initiating actor.
    if pending.act_id != act_id {
        return Err(ApiError::Conflict(
            "a sessão de assinatura não pertence a este ato".to_owned(),
        ));
    }
    if pending.actor != actor {
        return Err(ApiError::Forbidden(
            "apenas quem iniciou a assinatura a pode confirmar".to_owned(),
        ));
    }
    if OffsetDateTime::now_utc() >= pending.expires_at {
        // Expired: drop the stale session and report 410.
        consume_pending(&state, &pending.session_id).await;
        return Err(ApiError::Gone(
            "a sessão de assinatura expirou; reinicie a assinatura".to_owned(),
        ));
    }

    let session: CmdSignSession = serde_json::from_str(&pending.session_json)
        .map_err(|e| ApiError::Internal(format!("corrupt pending session: {e}")))?;
    let prepared: PreparedSignature = serde_json::from_str(&pending.prepared_json)
        .map_err(|e| ApiError::Internal(format!("corrupt prepared signature: {e}")))?;

    let cmd_cfg = resolve_cmd_config(&state).await?;
    // ValidateOtp → assemble the detached CMS. The OTP is consumed here.
    let cms = run_cmd_confirm(&state, &cmd_cfg, &session, &otp).await?;
    drop(otp);

    // Embed the CMS into the reserved placeholder → the B-B signed PDF.
    let signed_pdf = embed_signature(&prepared, &cms)
        .map_err(|e| ApiError::Internal(format!("failed to embed the CMS signature: {e}")))?;

    let final_pdf = finalize_signed_pdf(&state, signed_pdf, &session.signing_cert_der).await?;

    // Resolve the ledger scope from the live act (re-checking it is still sealed + unsigned).
    let scope = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        format!("entity:{}/book:{}/act:{}", entity.id, act.book_id, act.id)
    };

    let digest: [u8; 32] = Sha256::digest(&final_pdf.bytes).into();
    let signed_pdf_digest = crate::hex::hex(&digest);
    let signed_at = OffsetDateTime::now_utc();
    let trusted_list_status = session.trusted_list_status.map(status_label);
    // The source unsigned document id (for provenance in the event + row).
    let document_id = crate::documents::load_document(&state, act_id)
        .await?
        .map(|d| d.id)
        .unwrap_or_default();
    let stored = StoredSignedDocument {
        act_id,
        document_id: document_id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: FAMILY_CMD.to_owned(),
        evidentiary_level: EVIDENTIARY_QUALIFIED.to_owned(),
        trusted_list_status: trusted_list_status.clone(),
        signer_cert_subject: subject_dn(&session.signing_cert_der),
        signing_time: session.signing_time,
        signed_at,
        signer_cert_der: session.signing_cert_der.clone(),
        timestamp_token_der: final_pdf.timestamp_token_der.clone(),
        timestamp_trust_report_json: final_pdf.timestamp_trust_report_json.clone(),
        signed_pdf_bytes: final_pdf.bytes,
    };

    // Persist the signed variant + a chained `document.signed` event, and consume the pending
    // session — one durable commit. A chain-breaking append is rejected before the ledger mutates.
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": document_id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": FAMILY_CMD,
        "evidentiary_level": EVIDENTIARY_QUALIFIED,
        "trusted_list_status": trusted_list_status,
        "profile": pades_profile(final_pdf.timestamp_token_der.is_some()),
    });
    let payload = serde_json::to_vec(&event_payload)?;
    let session_id = pending.session_id.clone();
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| {
            tx.upsert_signed_document(&stored)?;
            tx.delete_pending_cmd_session(&session_id)
        })?;
        state.attest_latest(&attestor, &ledger).await;
    }
    // Publish to the live read models (GET source; the store is durability).
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());
    state.pending_signatures.write().await.remove(&session_id);

    Ok(Json(CmdConfirmResponse {
        document_id,
        act_id: act_id.to_string(),
        family: FAMILY_CMD,
        evidentiary_level: EVIDENTIARY_QUALIFIED,
        trusted_list_status,
        signed_at: rfc3339(signed_at),
        signed_pdf_digest,
        timestamp_token: final_pdf.report.has_signature_timestamp,
        finalization: "finalizado_qualificado",
    }))
}

// =================================================================================================
// Cartão de Cidadão (CC) — synchronous qualified signing (t58-e2)
// =================================================================================================
//
// Unlike CMD (two-phase: an SMS OTP arrives *between* two stateless HTTP requests), a CC signature
// is one synchronous local operation. The card, reader, Autenticação.gov middleware, and PIN entry
// all live on the SAME host as the API, and the PIN is entered *at the reader*, by the middleware,
// inside the single PKCS#11 `sign_digest` call — the PIN never enters this process (protected-
// authentication / NULL-PIN path). So CC needs no session, no persisted pending state, and no
// secret in the request body: one call takes the sealed unsigned PDF/A, drives the card on
// `spawn_blocking`, and persists the signed variant. It **reuses t57-S3's signed-document store row
// + `document.signed` ledger event + derived-status enforcement unchanged** (only the family
// differs), so no new web-asserted contract type is introduced.

/// The signing family a CC signature produces (matches `SigningFamily::CartaoDeCidadao`).
const FAMILY_CC: &str = "CartaoDeCidadao";

/// The `CHANCELA_LOCAL_SIGNING` co-location capability signal (t58 CC-B). The desktop shell sets it
/// on the embedded-server process (t58-e3) when the API is co-located with a card reader; a remote
/// `chancela-server` never does.
pub(crate) const LOCAL_SIGNING_ENV: &str = "CHANCELA_LOCAL_SIGNING";

/// Resolve the co-location signal from the environment. Mirrors the desktop's truthy parse (t58-e3):
/// any value other than blank / `0` / `false` / `off` / `no` counts as enabled, so the two halves
/// agree. Read once at [`AppState`](crate::AppState) construction into `AppState::local_signing`.
pub(crate) fn local_signing_from_env() -> bool {
    match std::env::var(LOCAL_SIGNING_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
        }
        Err(_) => false,
    }
}

/// Body of `POST /v1/acts/{id}/signature/cc/sign`. **Carries no secret** — the PIN is entered at the
/// card reader, driven by the Autenticação.gov middleware, and never enters this process.
#[derive(Deserialize)]
pub struct CcSignRequest {
    /// The capacity in which the signer acts (optional, informational — mirrors the CMD body).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Actor override for attribution.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful CC signature — the **same shape** as the CMD confirm response (t57-S3),
/// with `family: "CartaoDeCidadao"`. No new web-asserted type ⇒ no web contract drift.
#[derive(Serialize)]
pub struct CcSignResponse {
    /// The signed document's source (unsigned) document id.
    pub document_id: String,
    /// The owning act id.
    pub act_id: String,
    /// The family (`CartaoDeCidadao`).
    pub family: &'static str,
    /// The evidentiary level (`Qualified`).
    pub evidentiary_level: &'static str,
    /// The signer issuer's trusted-list status at signing time, if a policy was consulted.
    pub trusted_list_status: Option<String>,
    /// When the signature completed (RFC 3339).
    pub signed_at: String,
    /// Lowercase-hex sha-256 of the signed PDF bytes.
    pub signed_pdf_digest: String,
    /// Whether an RFC 3161 signature timestamp is present (B-T); always `false` for B-B.
    pub timestamp_token: bool,
    /// The derived finalization status (`finalizado_qualificado`).
    pub finalization: &'static str,
}

/// Body of `POST /v1/acts/{id}/signature/dss/attach`.
///
/// All entries are caller-supplied DER bytes encoded as base64. This endpoint does not fetch,
/// trust, or legally validate revocation material; it appends local DSS/VRI evidence to an already
/// signed PDF and reports the resulting technical evidence level only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DssAttachRequest {
    #[serde(
        default,
        alias = "certificates_base64",
        alias = "certificate_der_base64"
    )]
    pub certificates: Vec<String>,
    #[serde(default, alias = "ocsp_responses_base64", alias = "ocsp_der_base64")]
    pub ocsp_responses: Vec<String>,
    #[serde(default, alias = "crls_base64", alias = "crl_der_base64")]
    pub crls: Vec<String>,
    #[serde(default)]
    pub actor: Option<String>,
}

/// Body of `POST /v1/acts/{id}/signature/dss/collect-revocation`.
///
/// This live technical-upgrade seam uses the stored signer certificate from the signed artifact
/// and this caller-supplied issuer certificate to validate fetched CRL/OCSP evidence before DSS/VRI
/// attachment. It is deliberately opt-in and never claims production/legal B-LT.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DssCollectRevocationRequest {
    #[serde(alias = "issuer_certificate_base64", alias = "issuer_cert_der_base64")]
    pub issuer_certificate: String,
    /// Optional RFC 3339 validation time. Defaults to now, rounded to whole seconds.
    #[serde(default)]
    pub validation_time: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful local DSS/VRI evidence attachment.
#[derive(Serialize)]
pub struct DssAttachResponse {
    pub document_id: String,
    pub act_id: String,
    pub signed_pdf_digest: String,
    pub timestamp_token: bool,
    pub evidence: SignatureEvidenceStatus,
    pub evidentiary_level: &'static str,
    pub production_b_lt_status: &'static str,
    pub legal_b_lt_claimed: bool,
    pub status_scope: &'static str,
}

/// Response of a successful validated revocation collection + DSS/VRI attachment.
#[derive(Serialize)]
pub struct DssCollectRevocationResponse {
    pub document_id: String,
    pub act_id: String,
    pub signed_pdf_digest: String,
    pub timestamp_token: bool,
    pub evidence: SignatureEvidenceStatus,
    pub evidentiary_level: &'static str,
    pub production_b_lt_status: &'static str,
    pub legal_b_lt_claimed: bool,
    pub status_scope: &'static str,
    pub revocation: CollectedRevocationEvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectedRevocationEvidenceStatus {
    pub validation_time: String,
    pub discovered_ocsp_urls: Vec<String>,
    pub discovered_crl_urls: Vec<String>,
    pub ocsp_count: usize,
    pub crl_count: usize,
    pub certificate_count: usize,
    pub ocsp_sha256: Vec<String>,
    pub crl_sha256: Vec<String>,
    pub source_scope: &'static str,
    pub legal_b_lt_claimed: bool,
}

/// `POST /v1/acts/{id}/signature/cc/sign` — a synchronous Cartão de Cidadão qualified signature.
///
/// Loads the act's sealed unsigned PDF/A, drives the card on `spawn_blocking` (PKCS#11/PC/SC FFI +
/// human PIN entry at the reader both block), and — on success — persists the SIGNED variant + a
/// chained `document.signed` event, reusing t57-S3's store row and event unchanged. Only reachable
/// when the API is co-located with the reader (CC-B); a remote server 409s.
pub async fn sign_cc_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CcSignRequest>,
) -> Result<Json<CcSignResponse>, ApiError> {
    // RBAC (t64-E3): a qualified signature is `signing.perform` scoped to the act's book — the SAME
    // gate as the CMD endpoints. Checked first (before the co-location gate) so an unauthorized
    // caller is refused identically whether or not the host happens to be co-located.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let act_id = ActId(id);

    // Co-location gate (CC-B): CC needs the card + reader + middleware on the SAME host as the API.
    // The desktop embedded server sets `CHANCELA_LOCAL_SIGNING` (resolved into `local_signing` at
    // boot); a remote `chancela-server` never does, so CC is refused there — a remote server's
    // PKCS#11 can never reach a card in the client's pocket.
    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura com Cartão de Cidadão só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    // Resolve the act's sealed unsigned document, refusing a not-sealed act (signing is post-seal).
    {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        if act.ata_number.is_none() {
            return Err(ApiError::Conflict(
                "o ato ainda não foi selado; a assinatura qualificada é um passo posterior ao selo"
                    .to_owned(),
            ));
        }
    }
    let unsigned = crate::documents::load_document(&state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    // One qualified artifact per act (whether produced by CC or CMD).
    if load_signed(&state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem uma assinatura qualificada".to_owned(),
        ));
    }

    let tsl_source = configured_tsl_source(&state).await?;
    // A fixed signing time (whole seconds), carried into both the /Sig dict and the signed record.
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let reason = match req
        .capacity
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(capacity) => format!("Assinatura qualificada da ata ({capacity})"),
        None => "Assinatura qualificada da ata".to_owned(),
    };
    let opts = SignOptions {
        field_name: Some("Assinatura".to_owned()),
        signing_time: Some(pdf_time(signing_time)),
        reason: Some(reason),
        location: None,
        contact_info: None,
    };

    // Drive the card on `spawn_blocking` — the PKCS#11/PC/SC FFI and the human-paced PIN entry at
    // the reader both block, and must not stall the axum async runtime.
    let cc = run_cc_sign(&state, tsl_source, unsigned.pdf_bytes, signing_time, opts).await?;
    let final_pdf = finalize_signed_pdf(&state, cc.signed_pdf, &cc.signing_cert_der).await?;

    // Resolve the ledger scope from the live act (re-checking presence).
    let scope = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        format!("entity:{}/book:{}/act:{}", entity.id, act.book_id, act.id)
    };

    let digest: [u8; 32] = Sha256::digest(&final_pdf.bytes).into();
    let signed_pdf_digest = crate::hex::hex(&digest);
    let signed_at = OffsetDateTime::now_utc();
    let trusted_list_status = cc.trusted_list_status.map(status_label);
    let document_id = crate::documents::load_document(&state, act_id)
        .await?
        .map(|d| d.id)
        .unwrap_or_default();
    // Reuse t57-S3's F4 signed-document store row unchanged (family-agnostic columns).
    let stored = StoredSignedDocument {
        act_id,
        document_id: document_id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: FAMILY_CC.to_owned(),
        evidentiary_level: EVIDENTIARY_QUALIFIED.to_owned(),
        trusted_list_status: trusted_list_status.clone(),
        signer_cert_subject: subject_dn(&cc.signing_cert_der),
        signing_time,
        signed_at,
        signer_cert_der: cc.signing_cert_der.clone(),
        timestamp_token_der: final_pdf.timestamp_token_der.clone(),
        timestamp_trust_report_json: final_pdf.timestamp_trust_report_json.clone(),
        signed_pdf_bytes: final_pdf.bytes,
    };

    // Persist the signed variant + a chained `document.signed` event — one durable commit, the SAME
    // event/store path CMD uses (t57-S3). No secret anywhere (CC has no PIN/OTP in-process).
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": document_id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": FAMILY_CC,
        "evidentiary_level": EVIDENTIARY_QUALIFIED,
        "trusted_list_status": trusted_list_status,
        "profile": pades_profile(final_pdf.timestamp_token_der.is_some()),
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_signed_document(&stored))?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());

    Ok(Json(CcSignResponse {
        document_id,
        act_id: act_id.to_string(),
        family: FAMILY_CC,
        evidentiary_level: EVIDENTIARY_QUALIFIED,
        trusted_list_status,
        signed_at: rfc3339(signed_at),
        signed_pdf_digest,
        timestamp_token: final_pdf.report.has_signature_timestamp,
        finalization: "finalizado_qualificado",
    }))
}

/// `POST /v1/acts/{id}/signature/dss/attach` — append caller-supplied local DSS/VRI evidence to an
/// existing signed PDF.
///
/// This is a local technical-evidence endpoint only. It requires the act to already have a signed
/// PDF, accepts DER certificates/OCSP/CRLs supplied by the caller, appends them through the PAdES
/// DSS writer, re-validates the signed PDF, persists the updated bytes/digest, and chains a
/// separate audit event. It never claims production/legal LTV or B-LT conformance.
pub async fn attach_dss_evidence(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<DssAttachRequest>,
) -> Result<Json<DssAttachResponse>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    let mut stored = load_signed(&state, act_id)
        .await?
        .ok_or_else(|| ApiError::Conflict("o ato ainda não tem PDF assinado".to_owned()))?;

    // Re-check the existing artifact before appending a new DSS revision.
    validate_signed_pdf(&stored.signed_pdf_bytes, &stored.signer_cert_der)?;

    let evidence = dss_attach_evidence_from_request(req)?;
    let input_pdf = stored.signed_pdf_bytes.clone();
    let (updated_pdf, _) = tokio::task::spawn_blocking(move || {
        attach_pdf_dss(&input_pdf, &evidence).map_err(map_dss_attach_error)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("DSS attach task failed: {e}")))??;

    let report =
        validate_signed_pdf_with_incremental_updates(&updated_pdf, &stored.signer_cert_der)?;
    let signed_pdf_digest = sha256_hex(&updated_pdf);
    stored.signed_pdf_digest = signed_pdf_digest.clone();
    stored.signed_pdf_bytes = updated_pdf;

    let evidence_status = signature_evidence_status(Some(&stored));
    let audit_scope = act_audit_scope(&state, act_id).await?;
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": stored.document_id.clone(),
        "signed_pdf_digest": signed_pdf_digest.clone(),
        "evidentiary_level": evidence_status.current_level,
        "status_scope": TECHNICAL_EVIDENCE_ONLY,
        "production_b_lt_status": PRODUCTION_B_LT_NOT_CLAIMED,
        "legal_b_lt_claimed": false,
        "timestamp_token": report.has_signature_timestamp,
        "dss": &evidence_status.dss,
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &audit_scope,
            "document.signature.dss_attached",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_signed_document(&stored))?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());

    Ok(Json(DssAttachResponse {
        document_id: stored.document_id,
        act_id: act_id.to_string(),
        signed_pdf_digest,
        timestamp_token: evidence_status.timestamp_evidence_present,
        evidentiary_level: evidence_status.current_level,
        production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
        legal_b_lt_claimed: false,
        status_scope: TECHNICAL_EVIDENCE_ONLY,
        evidence: evidence_status,
    }))
}

/// `POST /v1/acts/{id}/signature/dss/collect-revocation` — collect validated CRL/OCSP evidence and
/// append it as local DSS/VRI technical evidence.
///
/// This is intentionally not part of the default signing completion path: it performs live
/// revocation I/O only when explicitly requested by a caller with `signing.perform`, uses the
/// already persisted signer certificate plus the supplied issuer certificate, writes `/TU`
/// validation freshness metadata, and keeps `legal_b_lt_claimed=false`.
pub async fn collect_revocation_evidence(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<DssCollectRevocationRequest>,
) -> Result<Json<DssCollectRevocationResponse>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    let mut stored = load_signed(&state, act_id)
        .await?
        .ok_or_else(|| ApiError::Conflict("o ato ainda não tem PDF assinado".to_owned()))?;

    validate_signed_pdf(&stored.signed_pdf_bytes, &stored.signer_cert_der)?;

    let issuer_cert_der = decode_single_der_base64("issuer_certificate", &req.issuer_certificate)?;
    let validation_time = match req.validation_time.as_deref() {
        Some(raw) => parse_rfc3339(raw, "validation_time")?,
        None => OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| OffsetDateTime::now_utc()),
    };
    let signer_cert_der = stored.signer_cert_der.clone();
    let input_pdf = stored.signed_pdf_bytes.clone();
    let (updated_pdf, collected) = tokio::task::spawn_blocking(move || {
        let provider = chancela_signing::RevocationEvidenceProvider::http();
        let collected = provider
            .collect_for_signer(&signer_cert_der, &issuer_cert_der, validation_time)
            .map_err(map_revocation_collect_error)?;
        let (updated_pdf, _) =
            attach_pdf_revocation_evidence(&input_pdf, &collected).map_err(map_dss_attach_error)?;
        Ok::<_, ApiError>((updated_pdf, collected))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("revocation collection task failed: {e}")))??;

    let report =
        validate_signed_pdf_with_incremental_updates(&updated_pdf, &stored.signer_cert_der)?;
    let signed_pdf_digest = sha256_hex(&updated_pdf);
    stored.signed_pdf_digest = signed_pdf_digest.clone();
    stored.signed_pdf_bytes = updated_pdf;

    let evidence_status = signature_evidence_status(Some(&stored));
    let revocation_status = collected_revocation_status(&collected);
    let audit_scope = act_audit_scope(&state, act_id).await?;
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": stored.document_id.clone(),
        "signed_pdf_digest": signed_pdf_digest.clone(),
        "evidentiary_level": evidence_status.current_level,
        "status_scope": TECHNICAL_EVIDENCE_ONLY,
        "production_b_lt_status": PRODUCTION_B_LT_NOT_CLAIMED,
        "legal_b_lt_claimed": false,
        "timestamp_token": report.has_signature_timestamp,
        "dss": &evidence_status.dss,
        "revocation": &revocation_status,
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &audit_scope,
            "document.signature.revocation_evidence_collected",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_signed_document(&stored))?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());

    Ok(Json(DssCollectRevocationResponse {
        document_id: stored.document_id,
        act_id: act_id.to_string(),
        signed_pdf_digest,
        timestamp_token: evidence_status.timestamp_evidence_present,
        evidentiary_level: evidence_status.current_level,
        production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
        legal_b_lt_claimed: false,
        status_scope: TECHNICAL_EVIDENCE_ONLY,
        evidence: evidence_status,
        revocation: revocation_status,
    }))
}

/// Drive the synchronous CC signature on `spawn_blocking`: build the trusted-list policy + the
/// smartcard provider, then run [`sign_pdf_cc`]. The provider is the injected key-backed test
/// provider (`cc_provider`), or the real co-located [`Pkcs11Token`]-backed [`SmartcardProvider`]
/// (production). The provider is built and consumed **inside** the blocking task, so it never
/// crosses a thread boundary.
async fn run_cc_sign(
    state: &AppState,
    tsl_source: Option<RuntimeTslSource>,
    pdf: Vec<u8>,
    signing_time: OffsetDateTime,
    opts: SignOptions,
) -> Result<CcSignedPdf, ApiError> {
    let policy_factory = state.cmd_trust_policy.clone();
    let provider_factory = state.cc_provider.clone();
    tokio::task::spawn_blocking(move || {
        let mut policy = build_trust_policy(policy_factory.clone(), tsl_source.clone())?;
        let provider: Box<dyn SignerProvider> = match provider_factory {
            Some(factory) => factory().map_err(map_cc_signing_error)?,
            None => Box::new(build_pkcs11_cc_provider()?),
        };
        sign_pdf_cc(
            provider.as_ref(),
            &pdf,
            signing_time,
            &opts,
            Some(policy.as_mut()),
        )
        .map_err(map_cc_signing_error)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("cc sign task failed: {e}")))?
}

/// Build the real Cartão de Cidadão provider for the co-located desktop deployment: open the
/// Autenticação.gov PKCS#11 token and wrap it as a [`SmartcardProvider`]. **Blocking** (PKCS#11/PC/SC
/// FFI) — only call inside `spawn_blocking`. A missing reader / absent middleware / no card is a
/// clean typed error surfaced as an honest 422, never a panic.
///
/// **CC-E (hardware-acceptance path, no CI coverage without a physical card):** the card exposes only
/// the signature leaf; the issuing-CA certificate for the trusted-list gate must be resolved
/// out-of-band (the leaf AKI against the TSL) and supplied via
/// [`SmartcardProvider::with_issuer_certificate`]. Until that resolution is wired the qualified gate
/// fails **closed** with `MissingIssuerCertificate` rather than trusting an unresolved issuer — the
/// safe default. Mock/CI runs inject `cc_provider` (issuer set) instead of taking this path.
fn build_pkcs11_cc_provider() -> Result<SmartcardProvider<Pkcs11Token>, ApiError> {
    let token = Pkcs11Token::open().map_err(|e| {
        ApiError::Unprocessable(format!(
            "não foi possível aceder ao Cartão de Cidadão (verifique o leitor e a aplicação \
             Autenticação.gov): {e}"
        ))
    })?;
    Ok(SmartcardProvider::new(token))
}

/// Map a [`chancela_signing::SigningError`] from the **CC** path to an [`ApiError`] with honest PT
/// messages, distinct from the internal PDF-structure (`Pades`) / CMS (`Cades`) errors. A provider
/// failure (card absent, PIN cancelled/wrong, signature not activated, reader missing) is
/// client-actionable → 422. No secret is ever echoed (the CC path holds none).
fn map_cc_signing_error(e: chancela_signing::SigningError) -> ApiError {
    use chancela_signing::SigningError as S;
    match e {
        S::UntrustedService { status } => ApiError::Unprocessable(format!(
            "o certificado do Cartão de Cidadão não está ativo na Lista de Confiança ({})",
            status_label(status)
        )),
        S::MissingIssuerCertificate => ApiError::Unprocessable(
            "não foi possível resolver o emissor do certificado do Cartão de Cidadão".to_owned(),
        ),
        // Where a card/PIN/activation/reader failure surfaces (distinct from Pades/Cades).
        S::Provider(msg) => ApiError::Unprocessable(format!(
            "não foi possível assinar com o Cartão de Cidadão (verifique o cartão, o leitor e o \
             PIN): {msg}"
        )),
        S::Cades(msg) | S::Pades(msg) => {
            ApiError::Internal(format!("falha ao montar a assinatura: {msg}"))
        }
        other => ApiError::Upstream(format!("falha no serviço de assinatura: {other}")),
    }
}

// =================================================================================================
// Generic provider-parameterized remote signing (t59-s3): CMD + any configured CSC QTSP behind one
// `RemoteSigningSource` seam.
// =================================================================================================
//
// t57's `/signature/cmd/*` endpoints (above) stay wired and byte-identical (the committed web
// consumes them). These provider-generic endpoints add ONE two-phase family that dispatches to a
// registry of `dyn RemoteSigningSource` — Chave Móvel Digital as the built-in provider `"cmd"`
// (`CmdRemoteSource`, byte-identical to the façade per t59-s1) plus one `CscRemoteSource` per
// configured external QTSP (Multicert / DigitalSign / …, provider id = its CSC config id). They
// reuse t57-S3's pending-session store, `document.signed` event, signed-variant persist, derived
// `require_qualified_for_seal` status, and TSL gate UNCHANGED — a CSC signature reports the same
// `SignatureStatusView`/`SignedInfo` shape with `family = "QualifiedCertificate"`, so there is no
// new web-asserted type and no contract drift.
//
// **Secrets (t59 ruling 5):** the signer's transient credential (PIN) / activation (OTP/SAD) are
// held in `Zeroizing`, consumed by the single call, and dropped — never persisted, logged, or
// echoed. A CSC provider's OAuth client secret comes from `CHANCELA_CSC_<PROVIDER>_*` env only, and
// only ever rides the transport's `Authorization` header; it never enters the session, the store,
// or an error message.

/// The status string a successful generic `initiate` returns (an activation is pending: an OTP was
/// dispatched, or the signer must authorize out-of-band at the provider).
const STATUS_ACTIVATION_PENDING: &str = "activation_pending";

// --- request / response DTOs (generic) --------------------------------------------------------

/// Body of `POST /v1/acts/{id}/signature/remote/{provider}/initiate`.
#[derive(Deserialize)]
pub struct RemoteInitiateRequest {
    /// The signer's public account reference at the provider (CMD: the citizen mobile in SCMD
    /// format `+351 XXXXXXXXX`; a CSC QTSP: the user / credential reference). Non-secret.
    pub user_ref: String,
    /// The signer's transient credential / PIN. **Consumed, never persisted/logged.** May be empty
    /// for a provider that carries no PIN (e.g. a user-OAuth CSC flow where activation is out-of-band).
    #[serde(default)]
    pub credential: String,
    /// The capacity in which the signer acts (optional, informational — mirrors the CMD body).
    #[serde(default)]
    pub capacity: Option<String>,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful generic initiate — **carries no secret** (no PIN, no OTP, no token).
#[derive(Serialize)]
pub struct RemoteInitiateResponse {
    /// The opaque pending-session id to submit with the activation at confirm.
    pub session_id: String,
    /// The resolved provider id that opened the session (`"cmd"`, `"multicert"`, …).
    pub provider_id: String,
    /// The signing family being produced (`ChaveMovelDigital` for CMD; `QualifiedCertificate` for CSC).
    pub family: String,
    /// The evidentiary level the produced signature will carry (`Qualified`).
    pub evidentiary_level: &'static str,
    /// Always [`STATUS_ACTIVATION_PENDING`] here (the activation has been dispatched / is pending).
    pub status: &'static str,
    /// A non-secret hint for the UI (a masked phone for CMD, or how to authorize for a CSC provider).
    pub activation_hint: String,
    /// When the pending session expires (RFC 3339).
    pub expires_at: String,
}

/// Body of `POST /v1/acts/{id}/signature/remote/{provider}/confirm`.
#[derive(Deserialize)]
pub struct RemoteConfirmRequest {
    /// The pending-session id returned by initiate.
    pub session_id: String,
    /// The signer's transient activation credential (the SMS OTP for CMD; the OTP/SAD for a CSC
    /// QTSP). **Consumed, never persisted/logged.**
    pub activation: String,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful generic confirm — the **same shape** as the CMD confirm response, plus
/// the resolved `provider_id`; `family` is a `String` so a CSC signature reports
/// `"QualifiedCertificate"` without a new web-asserted type.
#[derive(Serialize)]
pub struct RemoteConfirmResponse {
    /// The signed document's source (unsigned) document id.
    pub document_id: String,
    /// The owning act id.
    pub act_id: String,
    /// The resolved provider id (`"cmd"`, `"multicert"`, …).
    pub provider_id: String,
    /// The signing family (`ChaveMovelDigital` | `QualifiedCertificate`).
    pub family: String,
    /// The evidentiary level (`Qualified`).
    pub evidentiary_level: &'static str,
    /// The signer issuer's trusted-list status at signing time, if a policy was consulted.
    pub trusted_list_status: Option<String>,
    /// When the signature completed (RFC 3339).
    pub signed_at: String,
    /// Lowercase-hex sha-256 of the signed PDF bytes.
    pub signed_pdf_digest: String,
    /// Whether an RFC 3161 signature timestamp is present (B-T); always `false` for B-B.
    pub timestamp_token: bool,
    /// The derived finalization status (`finalizado_qualificado`).
    pub finalization: &'static str,
}

/// One entry in `GET /v1/signature/providers` — a non-secret picker row (t59 F4).
#[derive(Serialize)]
pub struct SignatureProviderView {
    /// The stable provider id (`"cmd"`, `"multicert"`, …) — the `{provider}` path segment.
    pub id: String,
    /// The signing family (`ChaveMovelDigital` | `QualifiedCertificate`).
    pub family: String,
    /// A human-readable label for the picker.
    pub label: String,
    /// The evidentiary level a signature from this provider carries (`Qualified`).
    pub evidentiary_level: &'static str,
    /// Whether the provider is configured (CMD: an ApplicationId resolves; CSC: its
    /// `CHANCELA_CSC_<PROVIDER>_*` credentials are present). **Never the secret itself.**
    pub configured: bool,
}

/// A resolved, configured remote-signing provider (carries its non-secret config).
enum ResolvedProvider {
    /// Chave Móvel Digital (the built-in provider `"cmd"`), with its resolved [`CmdConfig`].
    Cmd(CmdConfig),
    /// An external CSC-standard QTSP, with its non-secret [`CscConfig`].
    Csc(CscConfig),
}

// --- GET /v1/signature/providers --------------------------------------------------------------

/// `GET /v1/signature/providers` — the non-secret provider list for the signing picker (t59 F4).
///
/// Lists Chave Móvel Digital (always offered) plus every configured CSC QTSP, with a read-only
/// `configured` flag; **never** a secret. Gated with `signing.perform` at Global (the same signing
/// authority the initiate/confirm endpoints require) so a role without signing authority cannot
/// enumerate the providers.
pub async fn list_signature_providers(
    State(state): State<AppState>,
    actor: CurrentActor,
) -> Result<Json<Vec<SignatureProviderView>>, ApiError> {
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;

    let mut out = Vec::new();
    // Chave Móvel Digital — always offered; configured when an ApplicationId resolves (env/settings).
    out.push(SignatureProviderView {
        id: CMD_PROVIDER_ID.to_owned(),
        family: FAMILY_CMD.to_owned(),
        label: "Chave Móvel Digital".to_owned(),
        evidentiary_level: EVIDENTIARY_QUALIFIED,
        configured: resolve_cmd_config(&state).await.is_ok(),
    });
    // Every configured CSC QTSP. In tests the injected transport seam stands in for real creds.
    let di = state.csc_transport.is_some();
    for cfg in state.csc_providers.iter() {
        out.push(SignatureProviderView {
            id: cfg.provider_id.clone(),
            family: FAMILY_QUALIFIED.to_owned(),
            label: cfg.display_name.clone(),
            evidentiary_level: EVIDENTIARY_QUALIFIED,
            configured: di || CscSecrets::is_configured(&cfg.provider_id),
        });
    }
    Ok(Json(out))
}

// --- generic initiate -------------------------------------------------------------------------

/// `POST /v1/acts/{id}/signature/remote/{provider}/initiate` — phase 1 of a provider-generic
/// two-phase remote signature (CMD or a CSC QTSP). Mirrors [`initiate_cmd_signature`] but resolves
/// the provider from the `{provider}` path segment and drives it through `dyn RemoteSigningSource`.
pub async fn initiate_remote_signature(
    State(state): State<AppState>,
    Path((id, provider)): Path<(Uuid, String)>,
    actor: CurrentActor,
    Json(req): Json<RemoteInitiateRequest>,
) -> Result<Json<RemoteInitiateResponse>, ApiError> {
    // RBAC (t64): a qualified signature is `signing.perform` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    // Hold the credential (PIN) transiently: consumed by initiate, zeroized on drop. Never stored.
    let credential = Zeroizing::new(req.credential);
    let user_ref = req.user_ref.trim().to_string();
    let act_id = ActId(id);

    // Resolve + configuration-check the provider (422 for unknown / unconfigured / disabled).
    let resolved = resolve_provider(&state, &provider).await?;

    // CMD: reject an obviously-wrong phone early (the SCMD service is authoritative otherwise).
    if matches!(resolved, ResolvedProvider::Cmd(_)) && !looks_like_scmd_phone(&user_ref) {
        return Err(ApiError::Unprocessable(
            "número de telemóvel inválido para a Chave Móvel Digital (formato +351 XXXXXXXXX)"
                .to_owned(),
        ));
    }

    // Resolve the act's sealed unsigned document, refusing a not-sealed act (signing is post-seal).
    {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        if act.ata_number.is_none() {
            return Err(ApiError::Conflict(
                "o ato ainda não foi selado; a assinatura qualificada é um passo posterior ao selo"
                    .to_owned(),
            ));
        }
    }
    let unsigned = crate::documents::load_document(&state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    // One qualified artifact per act (whether produced by CMD, CC, or a CSC QTSP).
    if load_signed(&state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem uma assinatura qualificada".to_owned(),
        ));
    }

    let tsl_source = configured_tsl_source(&state).await?;

    // Prepare the PAdES incremental update (fixed whole-second signing time, carried into confirm).
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let reason = match req
        .capacity
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        Some(capacity) => format!("Assinatura qualificada da ata ({capacity})"),
        None => "Assinatura qualificada da ata".to_owned(),
    };
    let opts = SignOptions {
        field_name: Some("Assinatura".to_owned()),
        signing_time: Some(pdf_time(signing_time)),
        reason: Some(reason),
        location: None,
        contact_info: None,
    };
    let prepared = prepare_signature(&unsigned.pdf_bytes, &opts).map_err(|e| {
        ApiError::Unprocessable(format!(
            "não foi possível preparar o PDF para assinatura: {e}"
        ))
    })?;

    let doc_name = format!("ata-{}.pdf", act_id);
    // The non-secret display hint (a masked phone for CMD; how to authorize for a CSC provider).
    let activation_hint = match &resolved {
        ResolvedProvider::Cmd(_) => mask_phone(&user_ref),
        ResolvedProvider::Csc(cfg) => match cfg.authorization {
            CscAuthorization::User => "autorize a assinatura na aplicação do prestador".to_owned(),
            _ => "confirme com o código de ativação enviado".to_owned(),
        },
    };

    // Drive the provider's phase-1 (authenticate → cert → TSL gate → dispatch activation).
    let session = run_remote_initiate(
        &state,
        &resolved,
        user_ref,
        credential,
        doc_name.clone(),
        signing_time,
        prepared.clone(),
        tsl_source,
    )
    .await?;

    // Persist the non-secret pending session (durable + in-memory) so confirm survives the two
    // requests and a restart. The session blob is the serde `RemoteSignSession` (never a secret).
    let session_id = Uuid::new_v4().to_string();
    let expires_at = signing_time + time::Duration::seconds(SESSION_TTL_SECS);
    let provider_id = session.provider_id.clone();
    let family = family_label(&provider_id).to_owned();
    let pending = PendingCmdSession {
        session_id: session_id.clone(),
        act_id,
        actor,
        status: STATUS_ACTIVATION_PENDING.to_owned(),
        masked_phone: activation_hint.clone(),
        doc_name,
        session_json: serde_json::to_string(&session)?,
        prepared_json: serde_json::to_string(&prepared)?,
        created_at: signing_time,
        expires_at,
    };
    if let Some(store) = &state.store {
        store
            .persist(|tx| tx.upsert_pending_cmd_session(&pending))
            .map_err(|e| ApiError::Internal(format!("failed to persist pending session: {e}")))?;
    }
    state
        .pending_signatures
        .write()
        .await
        .insert(session_id.clone(), pending);

    Ok(Json(RemoteInitiateResponse {
        session_id,
        provider_id,
        family,
        evidentiary_level: EVIDENTIARY_QUALIFIED,
        status: STATUS_ACTIVATION_PENDING,
        activation_hint,
        expires_at: rfc3339(expires_at),
    }))
}

// --- generic confirm --------------------------------------------------------------------------

/// `POST /v1/acts/{id}/signature/remote/{provider}/confirm` — phase 2 of a provider-generic remote
/// signature. Mirrors [`confirm_cmd_signature`] but routes the confirm back to the provider that
/// opened the session (via `session.provider_id`) through `dyn RemoteSigningSource`, and reuses
/// t57-S3's signed-variant store + `document.signed` event + status enforcement UNCHANGED.
pub async fn confirm_remote_signature(
    State(state): State<AppState>,
    Path((id, provider)): Path<(Uuid, String)>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<RemoteConfirmRequest>,
) -> Result<Json<RemoteConfirmResponse>, ApiError> {
    // RBAC (t64): confirming a qualified signature is `signing.perform` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    // The activation (OTP/SAD) is transient: consumed by confirm, zeroized on drop. Never stored.
    let activation = Zeroizing::new(req.activation);
    let act_id = ActId(id);

    let pending = load_pending(&state, &req.session_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    // Session safety: single-use, act-scoped, gated to the initiating actor, TTL-bounded.
    if pending.act_id != act_id {
        return Err(ApiError::Conflict(
            "a sessão de assinatura não pertence a este ato".to_owned(),
        ));
    }
    if pending.actor != actor {
        return Err(ApiError::Forbidden(
            "apenas quem iniciou a assinatura a pode confirmar".to_owned(),
        ));
    }
    if OffsetDateTime::now_utc() >= pending.expires_at {
        consume_pending(&state, &pending.session_id).await;
        return Err(ApiError::Gone(
            "a sessão de assinatura expirou; reinicie a assinatura".to_owned(),
        ));
    }

    // The generic pending session persists a `RemoteSignSession` (not a `CmdSignSession`).
    let session: RemoteSignSession = serde_json::from_str(&pending.session_json)
        .map_err(|e| ApiError::Internal(format!("corrupt pending session: {e}")))?;
    let prepared: PreparedSignature = serde_json::from_str(&pending.prepared_json)
        .map_err(|e| ApiError::Internal(format!("corrupt prepared signature: {e}")))?;

    if session.provider_id != provider {
        return Err(ApiError::Conflict(
            "a sessão de assinatura pertence a outro prestador".to_owned(),
        ));
    }

    // Route the confirm back to the provider that opened the session (never client-asserted).
    let resolved = resolve_provider(&state, &session.provider_id).await?;
    let provider_id = session.provider_id.clone();
    let family = family_label(&provider_id);

    // Submit the activation → detached CAdES-B CMS. The activation is consumed here.
    let cms = run_remote_confirm(&state, &resolved, &session, activation).await?;

    // Embed the CMS into the reserved placeholder → the B-B signed PDF.
    let signed_pdf = embed_signature(&prepared, &cms)
        .map_err(|e| ApiError::Internal(format!("failed to embed the CMS signature: {e}")))?;

    let final_pdf = finalize_signed_pdf(&state, signed_pdf, &session.signing_cert_der).await?;

    // Resolve the ledger scope from the live act (re-checking presence).
    let scope = {
        let entities = state.entities.read().await;
        let books = state.books.read().await;
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
        let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
        format!("entity:{}/book:{}/act:{}", entity.id, act.book_id, act.id)
    };

    let digest: [u8; 32] = Sha256::digest(&final_pdf.bytes).into();
    let signed_pdf_digest = crate::hex::hex(&digest);
    let signed_at = OffsetDateTime::now_utc();
    let trusted_list_status = session.trusted_list_status.map(status_label);
    let document_id = crate::documents::load_document(&state, act_id)
        .await?
        .map(|d| d.id)
        .unwrap_or_default();
    // Reuse t57-S3's family-agnostic signed-document store row unchanged.
    let stored = StoredSignedDocument {
        act_id,
        document_id: document_id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: family.to_owned(),
        evidentiary_level: EVIDENTIARY_QUALIFIED.to_owned(),
        trusted_list_status: trusted_list_status.clone(),
        signer_cert_subject: subject_dn(&session.signing_cert_der),
        signing_time: session.signing_time,
        signed_at,
        signer_cert_der: session.signing_cert_der.clone(),
        timestamp_token_der: final_pdf.timestamp_token_der.clone(),
        timestamp_trust_report_json: final_pdf.timestamp_trust_report_json.clone(),
        signed_pdf_bytes: final_pdf.bytes,
    };

    // Persist the signed variant + a chained `document.signed` event, and consume the pending
    // session — one durable commit, the SAME event/store path CMD/CC use (t57-S3). The event
    // records the resolved `provider_id` for provenance (additive, not a web-asserted field).
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": document_id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": family,
        "provider_id": provider_id,
        "evidentiary_level": EVIDENTIARY_QUALIFIED,
        "trusted_list_status": trusted_list_status,
        "profile": pades_profile(final_pdf.timestamp_token_der.is_some()),
    });
    let payload = serde_json::to_vec(&event_payload)?;
    let session_id = pending.session_id.clone();
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| {
            tx.upsert_signed_document(&stored)?;
            tx.delete_pending_cmd_session(&session_id)
        })?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());
    state.pending_signatures.write().await.remove(&session_id);

    Ok(Json(RemoteConfirmResponse {
        document_id,
        act_id: act_id.to_string(),
        provider_id,
        family: family.to_owned(),
        evidentiary_level: EVIDENTIARY_QUALIFIED,
        trusted_list_status,
        signed_at: rfc3339(signed_at),
        signed_pdf_digest,
        timestamp_token: final_pdf.report.has_signature_timestamp,
        finalization: "finalizado_qualificado",
    }))
}

// --- provider registry + generic drivers ------------------------------------------------------

/// Resolve a `{provider}` id to a configured [`ResolvedProvider`], or a client-actionable 422 when
/// the provider is unknown or not configured/enabled (t59 F4). CMD is the built-in provider `"cmd"`;
/// every other id must match a configured CSC provider with credentials present.
async fn resolve_provider(
    state: &AppState,
    provider_id: &str,
) -> Result<ResolvedProvider, ApiError> {
    if provider_id == CMD_PROVIDER_ID {
        // A missing ApplicationId / a prod config without the AMA cert is a 422 (never a 500).
        let cfg = resolve_cmd_config(state).await?;
        return Ok(ResolvedProvider::Cmd(cfg));
    }
    let cfg = state
        .csc_providers
        .iter()
        .find(|c| c.provider_id == provider_id)
        .cloned()
        .ok_or_else(|| {
            ApiError::Unprocessable(format!(
                "prestador de assinatura desconhecido: '{provider_id}'"
            ))
        })?;
    // Configured? The injected transport seam stands in for real creds in tests; else env secrets.
    let configured = state.csc_transport.is_some() || CscSecrets::is_configured(&cfg.provider_id);
    if !configured {
        return Err(ApiError::Unprocessable(format!(
            "o prestador '{provider_id}' não está configurado (faltam as credenciais no ambiente)"
        )));
    }
    Ok(ResolvedProvider::Csc(cfg))
}

/// The signing-family label for a resolved provider id (CMD → `ChaveMovelDigital`; any CSC QTSP →
/// `QualifiedCertificate`).
fn family_label(provider_id: &str) -> &'static str {
    if provider_id == CMD_PROVIDER_ID {
        FAMILY_CMD
    } else {
        FAMILY_QUALIFIED
    }
}

/// Phase-1 driver: build the resolved provider's [`RemoteSigningSource`] and run `initiate` — inline
/// over an injected mock transport (tests, no network), or on `spawn_blocking` over a real HTTP
/// transport (production; the SCMD/CSC/TSL calls block and must not stall the async runtime).
#[allow(clippy::too_many_arguments)]
async fn run_remote_initiate(
    state: &AppState,
    resolved: &ResolvedProvider,
    user_ref: String,
    credential: Zeroizing<String>,
    doc_name: String,
    signing_time: OffsetDateTime,
    prepared: PreparedSignature,
    tsl_source: Option<RuntimeTslSource>,
) -> Result<RemoteSignSession, ApiError> {
    let policy_factory = state.cmd_trust_policy.clone();
    match resolved {
        ResolvedProvider::Cmd(cmd_cfg) => {
            if let Some(transport) = &state.cmd_transport {
                let client =
                    ScmdClient::from_config(SharedScmdTransport(transport.clone()), cmd_cfg)
                        .map_err(cmd_config_err)?;
                let source = CmdRemoteSource::new(client);
                let mut policy = build_trust_policy(policy_factory.clone(), tsl_source.clone())?;
                let init = RemoteInitiate {
                    user_ref: &user_ref,
                    credential: &credential,
                    doc_name: &doc_name,
                    signing_time,
                };
                source
                    .initiate(&init, &prepared, Some(policy.as_mut()))
                    .map_err(map_remote_error)
            } else {
                let cmd_cfg = cmd_cfg.clone();
                let policy_factory = policy_factory.clone();
                let tsl_source = tsl_source.clone();
                tokio::task::spawn_blocking(move || {
                    let transport =
                        HttpScmdTransport::from_config(&cmd_cfg).map_err(cmd_config_err)?;
                    let client =
                        ScmdClient::from_config(transport, &cmd_cfg).map_err(cmd_config_err)?;
                    let source = CmdRemoteSource::new(client);
                    let mut policy = build_trust_policy(policy_factory, tsl_source)?;
                    let init = RemoteInitiate {
                        user_ref: &user_ref,
                        credential: &credential,
                        doc_name: &doc_name,
                        signing_time,
                    };
                    source
                        .initiate(&init, &prepared, Some(policy.as_mut()))
                        .map_err(map_remote_error)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("remote initiate task failed: {e}")))?
            }
        }
        ResolvedProvider::Csc(config) => {
            if let Some(factory) = &state.csc_transport {
                let client = CscClient::new(
                    BoxedCscTransport(factory(config)),
                    config.clone(),
                    di_secrets(),
                );
                let source = CscRemoteSource::new(client);
                let mut policy = build_trust_policy(policy_factory.clone(), tsl_source.clone())?;
                let init = RemoteInitiate {
                    user_ref: &user_ref,
                    credential: &credential,
                    doc_name: &doc_name,
                    signing_time,
                };
                source
                    .initiate(&init, &prepared, Some(policy.as_mut()))
                    .map_err(map_remote_error)
            } else {
                // Production: env secrets (never persisted), real HTTP transport off the runtime.
                let secrets = CscSecrets::from_env(&config.provider_id).map_err(csc_config_err)?;
                let config = config.clone();
                let policy_factory = policy_factory.clone();
                let tsl_source = tsl_source.clone();
                tokio::task::spawn_blocking(move || {
                    let transport =
                        HttpCscTransport::new(&config.base_url).map_err(csc_config_err)?;
                    let client = CscClient::new(transport, config, secrets);
                    let source = CscRemoteSource::new(client);
                    let mut policy = build_trust_policy(policy_factory, tsl_source)?;
                    let init = RemoteInitiate {
                        user_ref: &user_ref,
                        credential: &credential,
                        doc_name: &doc_name,
                        signing_time,
                    };
                    source
                        .initiate(&init, &prepared, Some(policy.as_mut()))
                        .map_err(map_remote_error)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("remote initiate task failed: {e}")))?
            }
        }
    }
}

/// Phase-2 driver: build the resolved provider's [`RemoteSigningSource`] and run `confirm` — inline
/// over an injected mock transport (tests), or on `spawn_blocking` over a real HTTP transport
/// (production).
async fn run_remote_confirm(
    state: &AppState,
    resolved: &ResolvedProvider,
    session: &RemoteSignSession,
    activation: Zeroizing<String>,
) -> Result<Vec<u8>, ApiError> {
    match resolved {
        ResolvedProvider::Cmd(cmd_cfg) => {
            if let Some(transport) = &state.cmd_transport {
                let client =
                    ScmdClient::from_config(SharedScmdTransport(transport.clone()), cmd_cfg)
                        .map_err(cmd_config_err)?;
                let source = CmdRemoteSource::new(client);
                source
                    .confirm(session, &activation)
                    .map_err(map_remote_error)
            } else {
                let cmd_cfg = cmd_cfg.clone();
                let session = session.clone();
                tokio::task::spawn_blocking(move || {
                    let transport =
                        HttpScmdTransport::from_config(&cmd_cfg).map_err(cmd_config_err)?;
                    let client =
                        ScmdClient::from_config(transport, &cmd_cfg).map_err(cmd_config_err)?;
                    let source = CmdRemoteSource::new(client);
                    source
                        .confirm(&session, &activation)
                        .map_err(map_remote_error)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("remote confirm task failed: {e}")))?
            }
        }
        ResolvedProvider::Csc(config) => {
            if let Some(factory) = &state.csc_transport {
                let client = CscClient::new(
                    BoxedCscTransport(factory(config)),
                    config.clone(),
                    di_secrets(),
                );
                let source = CscRemoteSource::new(client);
                source
                    .confirm(session, &activation)
                    .map_err(map_remote_error)
            } else {
                let secrets = CscSecrets::from_env(&config.provider_id).map_err(csc_config_err)?;
                let config = config.clone();
                let session = session.clone();
                tokio::task::spawn_blocking(move || {
                    let transport =
                        HttpCscTransport::new(&config.base_url).map_err(csc_config_err)?;
                    let client = CscClient::new(transport, config, secrets);
                    let source = CscRemoteSource::new(client);
                    source
                        .confirm(&session, &activation)
                        .map_err(map_remote_error)
                })
                .await
                .map_err(|e| ApiError::Internal(format!("remote confirm task failed: {e}")))?
            }
        }
    }
}

/// A local newtype so an injected boxed `dyn CscTransport` can be handed to [`CscClient`] (which
/// needs a concrete `T: CscTransport`). Delegates every call. Mirrors [`SharedScmdTransport`].
struct BoxedCscTransport(Box<dyn CscTransport + Send>);

impl CscTransport for BoxedCscTransport {
    fn post_json(
        &self,
        path: &str,
        auth: CscAuthHeader<'_>,
        body: &str,
    ) -> Result<String, CscError> {
        self.0.post_json(path, auth, body)
    }
}

/// Placeholder CSC secrets used ONLY when the DI transport seam is injected (tests): a
/// [`MockCscTransport`](chancela_csc::MockCscTransport) ignores the client secret (it never reaches
/// a real endpoint), so no real credential is needed to exercise the handler flow. Production loads
/// the real secrets from `CHANCELA_CSC_<PROVIDER>_*` env vars via [`CscSecrets::from_env`].
fn di_secrets() -> CscSecrets {
    CscSecrets::new("chancela-di-client", "chancela-di-secret")
}

/// A CSC configuration/transport failure is a client-actionable 422, never echoing a secret.
fn csc_config_err(e: CscError) -> ApiError {
    ApiError::Unprocessable(format!(
        "configuração do prestador de assinatura inválida: {e}"
    ))
}

/// Map a [`chancela_signing::SigningError`] from a **generic** remote provider (CMD or a CSC QTSP)
/// to an [`ApiError`], never echoing a secret. A provider rejection (wrong OTP/SAD, service refusal)
/// is a clean 422; an untrusted issuer / missing issuer is a client-actionable 422; a CMS/PDF
/// assembly fault is a 500.
fn map_remote_error(e: chancela_signing::SigningError) -> ApiError {
    use chancela_signing::SigningError as S;
    match e {
        S::UntrustedService { status } => ApiError::Unprocessable(format!(
            "o serviço de confiança do signatário não está ativo na Lista de Confiança ({})",
            status_label(status)
        )),
        S::MissingIssuerCertificate => ApiError::Unprocessable(
            "não foi possível resolver o emissor do certificado do signatário".to_owned(),
        ),
        S::Provider(msg) => {
            ApiError::Unprocessable(format!("o prestador de assinatura recusou o pedido: {msg}"))
        }
        S::Cades(msg) | S::Pades(msg) => {
            ApiError::Internal(format!("falha ao montar a assinatura: {msg}"))
        }
        other => ApiError::Upstream(format!("falha no serviço de assinatura: {other}")),
    }
}

/// Load the configured CSC remote-signing providers from the environment (t59-s3 / drift-safe env
/// config shape). The provider LIST + non-secret selectors come from `CHANCELA_CSC_*` env vars —
/// **never** the web-asserted `/v1/settings` document — so adding a provider never drifts a web
/// contract fixture. Secrets stay in `CHANCELA_CSC_<PROVIDER>_{CLIENT_ID,CLIENT_SECRET,ACCESS_TOKEN}`
/// (loaded separately by [`CscSecrets::from_env`]), never here.
///
/// Env shape (`<P>` = the upper-cased, non-alphanumeric-sanitized provider id):
/// - `CHANCELA_CSC_PROVIDERS` — comma/space/`;`-separated provider ids to enable (unset → none).
/// - `CHANCELA_CSC_<P>_BASE_URL` — the provider's CSC v2 base URL (**required**; a provider missing
///   it, or failing [`CscConfig::validate`], is skipped with a warning).
/// - `CHANCELA_CSC_<P>_DISPLAY_NAME` — the UI picker label (default: the provider id).
/// - `CHANCELA_CSC_<P>_AUTHORIZATION` — `service` (default) | `user`.
/// - `CHANCELA_CSC_<P>_SANDBOX` — truthy/falsey (default `true`).
/// - `CHANCELA_CSC_<P>_CREDENTIAL_ID` — a pre-selected credential id (optional).
/// - `CHANCELA_CSC_<P>_SCOPE` — the OAuth2 scope (default `service`).
pub(crate) fn load_csc_providers_from_env() -> Vec<CscConfig> {
    let list = match std::env::var("CHANCELA_CSC_PROVIDERS") {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for id in list
        .split([',', ' ', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let prefix = csc_env_prefix(id);
        let var = |suffix: &str| -> Option<String> {
            std::env::var(format!("{prefix}_{suffix}"))
                .ok()
                .filter(|v| !v.trim().is_empty())
        };
        let Some(base_url) = var("BASE_URL") else {
            eprintln!("chancela-csc: provider '{id}' has no {prefix}_BASE_URL; skipping");
            continue;
        };
        let authorization = var("AUTHORIZATION")
            .and_then(|s| CscAuthorization::parse(s.trim()).ok())
            .unwrap_or(CscAuthorization::Service);
        let sandbox = var("SANDBOX")
            .map(|s| {
                !matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "off" | "no"
                )
            })
            .unwrap_or(true);
        let cfg = CscConfig {
            provider_id: id.to_owned(),
            display_name: var("DISPLAY_NAME").unwrap_or_else(|| id.to_owned()),
            base_url,
            authorization,
            sandbox,
            credential_id: var("CREDENTIAL_ID"),
            scope: var("SCOPE").unwrap_or_else(|| chancela_csc::DEFAULT_SCOPE.to_owned()),
        };
        if let Err(e) = cfg.validate() {
            eprintln!("chancela-csc: provider '{id}' config invalid ({e}); skipping");
            continue;
        }
        out.push(cfg);
    }
    out
}

/// The `CHANCELA_CSC_<PROVIDER>` env-var prefix for a provider id (upper-cased; non-alphanumeric →
/// `_`). Kept in sync with `chancela_csc::CscConfig::env_prefix` (a small duplication so the api need
/// not construct a config just to read the prefix).
fn csc_env_prefix(provider_id: &str) -> String {
    let sanitized: String = provider_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("CHANCELA_CSC_{sanitized}")
}

fn pades_profile(has_timestamp: bool) -> &'static str {
    if has_timestamp {
        PADES_PROFILE_B_T
    } else {
        PADES_PROFILE_B_B
    }
}

// --- official import --------------------------------------------------------------------------

/// `POST /v1/acts/{id}/signature/official/import` — import a signed PDF produced outside Chancela
/// through the official Autenticação.gov app/middleware/provider UI.
///
/// This is a user-mediated handoff: Chancela validates that the upload is a signed PAdES PDF and
/// that its bytes extend this act's sealed PDF, then stores the uploaded bytes unchanged as
/// technical imported evidence. It does not accept secrets and does not claim TSL-backed qualified
/// or legal completion.
pub async fn import_official_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<OfficialSignatureImportResponse>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;

    let candidate = official_import_candidate_from_request(&headers, &body)?;
    let client_metadata_present = candidate.has_client_metadata();
    let actor = actor.resolve(candidate.actor.as_deref().unwrap_or("api"));

    let sealed = {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        act.ata_number.is_some()
    };
    if !sealed {
        return Err(ApiError::Conflict(
            "o ato ainda não foi selado; a importação de assinatura oficial é posterior ao selo"
                .to_owned(),
        ));
    }

    let unsigned = crate::documents::load_document(&state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    if load_signed(&state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem um artefacto de assinatura".to_owned(),
        ));
    }

    let signed_pdf = candidate.signed_pdf_bytes;
    if signed_pdf.is_empty() {
        return Err(ApiError::Unprocessable(
            "signed PDF upload is empty".to_owned(),
        ));
    }
    if signed_pdf.len() > OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "signed PDF upload is {} bytes; import accepts at most {} bytes",
            signed_pdf.len(),
            OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES
        )));
    }

    let report = validate_imported_signed_pdf(&signed_pdf)?;
    if !signed_pdf.starts_with(&unsigned.pdf_bytes) {
        return Err(ApiError::Conflict(
            "o PDF assinado não corresponde ao PDF selado deste ato".to_owned(),
        ));
    }

    let signed_pdf_digest = sha256_hex(&signed_pdf);
    let signed_at = OffsetDateTime::now_utc();
    let signing_time = report.cades.signing_time.unwrap_or(signed_at);
    let signer_cert_der = report.cades.signer_cert_der.clone();
    let timestamp_token = report.has_signature_timestamp;
    let legal_validation = official_import_legal_validation();
    let finalization = {
        let require_qualified = state
            .settings
            .read()
            .await
            .signing
            .require_qualified_for_seal;
        finalization_status(true, false, require_qualified)
    };

    let stored = StoredSignedDocument {
        act_id,
        document_id: unsigned.id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: FAMILY_OFFICIAL_HANDOFF.to_owned(),
        evidentiary_level: EVIDENTIARY_IMPORTED_OFFICIAL.to_owned(),
        trusted_list_status: None,
        signer_cert_subject: subject_dn(&signer_cert_der),
        signing_time,
        signed_at,
        signer_cert_der,
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        signed_pdf_bytes: signed_pdf,
    };

    let audit_scope = act_audit_scope(&state, act_id).await?;
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": unsigned.id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": FAMILY_OFFICIAL_HANDOFF,
        "evidentiary_level": EVIDENTIARY_IMPORTED_OFFICIAL,
        "trusted_list_status": null,
        "profile": pades_profile(timestamp_token),
        "legal_validation": legal_validation.clone(),
        "validation": {
            "pades_cryptographic_validation": "valid",
            "byte_range_covers_whole_file_except_contents": true,
            "sealed_pdf_prefix_match": true,
            "trust_validation": "not_performed",
            "qualified_status_claimed": false
        },
        "client_declared_metadata": {
            "present": client_metadata_present,
            "authoritative": false
        }
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &audit_scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_signed_document(&stored))?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());

    Ok(Json(OfficialSignatureImportResponse {
        document_id: stored.document_id,
        act_id: act_id.to_string(),
        family: FAMILY_OFFICIAL_HANDOFF,
        evidentiary_level: EVIDENTIARY_IMPORTED_OFFICIAL,
        trusted_list_status: None,
        legal_validation,
        signing_time: rfc3339(signing_time),
        signed_at: rfc3339(signed_at),
        signed_pdf_digest,
        timestamp_token,
        finalization,
        qualification_claimed: false,
        client_metadata_authoritative: false,
    }))
}

/// `POST /v1/acts/{id}/signature/local/pkcs12/sign` — sign a sealed act with a locally supplied
/// PKCS#12/PFX software certificate.
///
/// This is an explicit advanced local-signing flow. The request's encrypted PFX bytes and
/// passphrase are transient inputs only; the persisted artifact is the resulting signed PDF plus
/// public certificate/audit evidence. No trusted-list lookup is performed and no qualified
/// remote/CMD status is claimed.
pub async fn sign_local_pkcs12_signature(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<LocalPkcs12SignRequest>,
) -> Result<Json<LocalPkcs12SignResponse>, ApiError> {
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let act_id = ActId(id);

    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura local com certificado PKCS#12 só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        if act.ata_number.is_none() {
            return Err(ApiError::Conflict(
                "o ato ainda não foi selado; a assinatura local é um passo posterior ao selo"
                    .to_owned(),
            ));
        }
    }

    let unsigned = crate::documents::load_document(&state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    if load_signed(&state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem um artefacto de assinatura".to_owned(),
        ));
    }

    let pkcs12_der =
        Zeroizing::new(B64.decode(req.pkcs12_base64.trim()).map_err(|e| {
            ApiError::Unprocessable(format!("invalid base64 PKCS#12 content: {e}"))
        })?);
    if pkcs12_der.is_empty() {
        return Err(ApiError::Unprocessable(
            "PKCS#12 upload is empty".to_owned(),
        ));
    }
    if pkcs12_der.len() > LOCAL_PKCS12_SIGN_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "PKCS#12 upload is {} bytes; local signing accepts at most {} bytes",
            pkcs12_der.len(),
            LOCAL_PKCS12_SIGN_MAX_BYTES
        )));
    }

    let passphrase = Zeroizing::new(req.passphrase);
    let friendly_name = optional_trimmed(req.friendly_name);
    let selector = friendly_name
        .clone()
        .map(Pkcs12IdentitySelector::by_friendly_name)
        .unwrap_or_else(Pkcs12IdentitySelector::any);
    let capacity = optional_trimmed(req.capacity);
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let reason = match capacity.as_deref() {
        Some(capacity) => format!("Assinatura local avancada da ata ({capacity})"),
        None => "Assinatura local avancada da ata".to_owned(),
    };
    let opts = SignOptions {
        field_name: Some("AssinaturaLocalPkcs12".to_owned()),
        signing_time: Some(pdf_time(signing_time)),
        reason: Some(reason),
        location: None,
        contact_info: None,
    };
    let unsigned_pdf = unsigned.pdf_bytes.clone();

    let (signed_pdf, identity) = tokio::task::spawn_blocking(move || {
        let source = Pkcs12SigningSource::from_der_with_selector(
            pkcs12_der.as_slice(),
            &passphrase,
            &selector,
        )?;
        let identity = source.identity().clone();
        let signed_pdf = sign_pdf_pades(&source, &unsigned_pdf, signing_time, &opts)?;
        Ok::<_, chancela_signing::SigningError>((signed_pdf, identity))
    })
    .await
    .map_err(|e| ApiError::Internal(format!("local PKCS#12 signing task failed: {e}")))?
    .map_err(map_local_pkcs12_signing_error)?;

    let final_pdf =
        finalize_signed_pdf(&state, signed_pdf, &identity.signing_certificate_der).await?;
    let signed_pdf_digest = sha256_hex(&final_pdf.bytes);
    let signed_at = OffsetDateTime::now_utc();
    let signer_cert_subject = subject_dn(&identity.signing_certificate_der);
    let signer_cert_sha256 = sha256_hex(&identity.signing_certificate_der);
    let finalization = {
        let require_qualified = state
            .settings
            .read()
            .await
            .signing
            .require_qualified_for_seal;
        finalization_status(true, false, require_qualified)
    };

    let stored = StoredSignedDocument {
        act_id,
        document_id: unsigned.id.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: FAMILY_LOCAL_PKCS12.to_owned(),
        evidentiary_level: EVIDENTIARY_ADVANCED_LOCAL.to_owned(),
        trusted_list_status: None,
        signer_cert_subject: signer_cert_subject.clone(),
        signing_time,
        signed_at,
        signer_cert_der: identity.signing_certificate_der.clone(),
        timestamp_token_der: final_pdf.timestamp_token_der.clone(),
        timestamp_trust_report_json: final_pdf.timestamp_trust_report_json.clone(),
        signed_pdf_bytes: final_pdf.bytes,
    };

    let audit_scope = act_audit_scope(&state, act_id).await?;
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": unsigned.id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": FAMILY_LOCAL_PKCS12,
        "evidentiary_level": EVIDENTIARY_ADVANCED_LOCAL,
        "trusted_list_status": null,
        "profile": pades_profile(final_pdf.timestamp_token_der.is_some()),
        "signer_cert_sha256": signer_cert_sha256,
        "certificate_chain_count": identity.chain_der.len(),
        "source": {
            "kind": "local_pkcs12_software_certificate",
            "friendly_name_selected": friendly_name,
            "secret_material_persisted": false,
            "passphrase_persisted": false,
            "pkcs12_persisted": false
        },
        "validation": {
            "pades_cryptographic_validation": "valid",
            "byte_range_covers_whole_file_except_contents": true,
            "trust_validation": "not_performed",
            "qualified_status_claimed": false,
            "qualified_remote_cmd_signature": false
        },
        "status_scope": LOCAL_TECHNICAL_EVIDENCE_ONLY,
        "notice": LOCAL_PKCS12_NOTICE
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &audit_scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| tx.upsert_signed_document(&stored))?;
        state.attest_latest(&attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(act_id, stored.clone());

    Ok(Json(LocalPkcs12SignResponse {
        document_id: stored.document_id,
        act_id: act_id.to_string(),
        family: FAMILY_LOCAL_PKCS12,
        evidentiary_level: EVIDENTIARY_ADVANCED_LOCAL,
        trusted_list_status: None,
        signing_time: rfc3339(signing_time),
        signed_at: rfc3339(signed_at),
        signed_pdf_digest,
        signer_cert_subject,
        signer_cert_sha256,
        certificate_chain_count: identity.chain_der.len(),
        timestamp_token: final_pdf.report.has_signature_timestamp,
        finalization,
        qualification_claimed: false,
        legal_status_claimed: false,
        status_scope: LOCAL_TECHNICAL_EVIDENCE_ONLY,
        notice: LOCAL_PKCS12_NOTICE,
    }))
}

// --- status / read ----------------------------------------------------------------------------

/// `GET /v1/acts/{id}/signature` — the act's signature status + derived finalization.
pub async fn get_signature_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Json<SignatureStatusView>, ApiError> {
    // RBAC (t64-E3): reading signature status is `act.read` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let act_id = ActId(id);
    let sealed = {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        act.ata_number.is_some()
    };
    let require_qualified = state
        .settings
        .read()
        .await
        .signing
        .require_qualified_for_seal;

    if let Some(signed) = load_signed(&state, act_id).await? {
        let qualified = is_qualified_signed(&signed);
        let evidence = signature_evidence_status(Some(&signed));
        return Ok(Json(SignatureStatusView {
            status: "signed",
            finalization: finalization_status(sealed, qualified, require_qualified),
            require_qualified_for_seal: require_qualified,
            signed: Some(SignedInfo {
                family: signed.signature_family,
                evidentiary_level: signed.evidentiary_level,
                trusted_list_status: signed.trusted_list_status,
                signer_cert_subject: signed.signer_cert_subject,
                signing_time: rfc3339(signed.signing_time),
                signed_at: rfc3339(signed.signed_at),
                signed_pdf_digest: signed.signed_pdf_digest,
                timestamp_token: evidence.timestamp_evidence_present,
                download: format!("/v1/acts/{id}/document/signed"),
            }),
            pending: None,
            evidence,
        }));
    }

    if let Some(pending) = find_pending_for_act(&state, act_id).await {
        // A pending session that has already expired is reported as unsigned (not pending).
        if OffsetDateTime::now_utc() < pending.expires_at {
            return Ok(Json(SignatureStatusView {
                status: "pending",
                finalization: finalization_status(sealed, false, require_qualified),
                require_qualified_for_seal: require_qualified,
                signed: None,
                pending: Some(PendingInfo {
                    session_id: pending.session_id,
                    masked_phone: pending.masked_phone,
                    expires_at: rfc3339(pending.expires_at),
                }),
                evidence: signature_evidence_status(None),
            }));
        }
    }

    Ok(Json(SignatureStatusView {
        status: "unsigned",
        finalization: finalization_status(sealed, false, require_qualified),
        require_qualified_for_seal: require_qualified,
        signed: None,
        pending: None,
        evidence: signature_evidence_status(None),
    }))
}

/// `GET /v1/acts/{id}/document/signed` — the SIGNED PDF bytes (`application/pdf`); `404` until the
/// act carries a qualified signature.
pub async fn get_signed_document_pdf(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    // RBAC (t64-E3): reading the signed PDF is `act.read` scoped to the act's book.
    let scope = scope_of_act(&state, ActId(id)).await;
    require_permission(&state, &actor, Permission::ActRead, scope).await?;
    let signed = load_signed(&state, ActId(id))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok((
        [(header::CONTENT_TYPE, "application/pdf")],
        signed.signed_pdf_bytes,
    )
        .into_response())
}

// --- enforcement (deliverable D) --------------------------------------------------------------

/// Derive the finalization status from the seal + qualified-signature state and the enforcement
/// setting (t57 ruling 6). `signed` here means a validated `Qualified` signed variant exists.
///
/// - a qualified signature present ⇒ `finalizado_qualificado`
/// - not sealed ⇒ `rascunho`
/// - sealed, `require_qualified` ON, no qualified signature ⇒ `aguarda_assinatura_qualificada`
/// - sealed, `require_qualified` OFF ⇒ `finalizado` (the non-qualified path stays usable)
pub(crate) fn finalization_status(
    sealed: bool,
    signed: bool,
    require_qualified: bool,
) -> &'static str {
    if signed {
        "finalizado_qualificado"
    } else if !sealed {
        "rascunho"
    } else if require_qualified {
        "aguarda_assinatura_qualificada"
    } else {
        "finalizado"
    }
}

fn signature_evidence_status(signed: Option<&StoredSignedDocument>) -> SignatureEvidenceStatus {
    let pades_report =
        signed.and_then(|doc| chancela_pades::validate_pdf_signature(&doc.signed_pdf_bytes).ok());
    let timestamped = signed.is_some_and(|doc| doc.timestamp_token_der.is_some())
        || pades_report
            .as_ref()
            .is_some_and(|report| report.has_signature_timestamp);
    let dss = match (pades_report.as_ref(), signed) {
        (Some(report), _) => DssEvidenceStatus::from_report(&report.dss),
        (None, Some(doc)) => dss_evidence_status(&doc.signed_pdf_bytes),
        (None, None) => DssEvidenceStatus::not_applicable(),
    };
    let doc_timestamp = match (pades_report.as_ref(), signed) {
        (Some(report), _) => DocTimeStampEvidenceStatus::from_report(&report.doc_timestamps),
        (None, Some(doc)) => doc_timestamp_evidence_status(&doc.signed_pdf_bytes),
        (None, None) => DocTimeStampEvidenceStatus::not_applicable(),
    };
    let local_technical_renewal_plan = match (pades_report.as_ref(), signed.is_some()) {
        (Some(report), _) => renewal_plan_evidence_status(&report.ltv_renewal_plan),
        (None, true) => LocalTechnicalRenewalPlanEvidenceStatus::unavailable(),
        (None, false) => LocalTechnicalRenewalPlanEvidenceStatus::not_applicable(),
    };
    let dss_evidence_present = dss.present || dss.vri_count > 0 || dss.revocation_evidence_present;
    let local_b_lt_style_evidence_present = timestamped && dss.revocation_evidence_present;
    let local_b_lt_style_evidence_partial =
        !local_b_lt_style_evidence_present && dss_evidence_present;
    let local_b_lta_technical_evidence_present =
        local_b_lt_style_evidence_present && doc_timestamp.all_imprints_valid;
    let local_b_lta_technical_evidence_partial =
        !local_b_lta_technical_evidence_present && doc_timestamp.present;
    let current_level = match (
        signed.is_some(),
        timestamped,
        local_b_lt_style_evidence_present,
        local_b_lta_technical_evidence_present,
    ) {
        (false, _, _, _) => EVIDENCE_LEVEL_UNSIGNED,
        (true, _, _, true) => EVIDENCE_LEVEL_B_LTA_LOCAL,
        (true, _, true, false) => EVIDENCE_LEVEL_B_LT_LOCAL,
        (true, true, false, false) => EVIDENCE_LEVEL_B_T,
        (true, false, false, false) => EVIDENCE_LEVEL_B_B,
    };
    let dss_revocation_evidence_status = match (signed.is_some(), dss.inspection_status) {
        (false, _) => DSS_REVOCATION_NOT_APPLICABLE,
        (true, DSS_INSPECTION_UNAVAILABLE) => DSS_REVOCATION_INSPECTION_UNAVAILABLE,
        (true, _) if !dss.revocation_evidence_present => DSS_REVOCATION_NOT_PRESENT,
        (true, _) if timestamped => DSS_REVOCATION_LOCAL_TECHNICAL_ONLY,
        (true, _) => DSS_REVOCATION_PRESENT_WITHOUT_TIMESTAMP,
    };
    let mut long_term_status = Vec::with_capacity(5);
    if timestamped {
        long_term_status.push(LongTermEvidenceStatus::Timestamped);
    } else {
        long_term_status.push(LongTermEvidenceStatus::NotConfigured);
    }
    if local_b_lt_style_evidence_present {
        long_term_status.push(LongTermEvidenceStatus::LtLocalTechnicalEvidence);
    } else if local_b_lt_style_evidence_partial {
        long_term_status.push(LongTermEvidenceStatus::LtLocalTechnicalEvidencePartial);
    } else {
        long_term_status.push(LongTermEvidenceStatus::LtNotImplemented);
    }
    long_term_status.push(LongTermEvidenceStatus::LtProductionNotClaimed);
    if local_b_lta_technical_evidence_present {
        long_term_status.push(LongTermEvidenceStatus::LtaLocalTechnicalEvidence);
    } else if local_b_lta_technical_evidence_partial {
        long_term_status.push(LongTermEvidenceStatus::LtaLocalTechnicalEvidencePartial);
    } else {
        long_term_status.push(LongTermEvidenceStatus::LtaNotImplemented);
    }

    SignatureEvidenceStatus {
        current_level,
        timestamp_evidence_present: timestamped,
        dss_revocation_evidence_present: dss.revocation_evidence_present,
        dss_revocation_evidence_status,
        dss,
        doc_timestamp,
        local_b_lt_style_evidence_present,
        production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
        live_revocation_fetching: false,
        legal_b_lt_claimed: false,
        legal_b_lta_claimed: false,
        renewal_policy: RenewalPolicyEvidenceStatus::not_configured(),
        local_technical_renewal_plan,
        long_term_status,
        timestamp_trust: signed.and_then(timestamp_trust_status_from_persisted_metadata),
        status_scope: TECHNICAL_EVIDENCE_ONLY,
    }
}

fn timestamp_trust_status_from_persisted_metadata(
    signed: &StoredSignedDocument,
) -> Option<TimestampTrustEvidenceStatus> {
    signed
        .timestamp_trust_report_json
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
}

/// Build the wire/status diagnostics for technical timestamp trust from already-verified
/// RFC 3161 and authenticated QTST inputs.
#[allow(dead_code)]
pub fn timestamp_trust_evidence_status(
    timestamp: &chancela_tsa::Timestamp,
    qtst: &chancela_tsl::QtstMatchDetails,
    policy: &TimestampTrustPolicy,
) -> TimestampTrustEvidenceStatus {
    TimestampTrustEvidenceStatus::from(validate_timestamp_trust(timestamp, qtst, policy))
}

impl From<TimestampTrustReport> for TimestampTrustEvidenceStatus {
    fn from(report: TimestampTrustReport) -> Self {
        let decision = match report.decision {
            TimestampTrustDecision::Accepted => "accepted",
            TimestampTrustDecision::Rejected => "rejected",
            _ => "rejected",
        };
        let qtst_status = match report.trusted_list_status {
            TrustedListStatus::Granted => "granted",
            TrustedListStatus::Withdrawn => "withdrawn",
            TrustedListStatus::Unknown => "unknown",
            _ => "unknown",
        };
        Self {
            decision: decision.to_owned(),
            policy_oid: report.timestamp_policy_oid,
            policy_oid_accepted: report.policy_oid_accepted,
            tsa_certificate_embedded: report.tsa_certificate_embedded,
            embedded_certificate_count: report.embedded_certificate_count,
            qtst_status: qtst_status.to_owned(),
            qtst_authenticated: report.trusted_list_authenticated,
            qtst_matches: report
                .qtst_matches
                .into_iter()
                .map(|m| TimestampQtstMatchEvidenceStatus {
                    provider_name: m.provider_name,
                    service_name: m.service_name,
                    granted_and_effective: m.granted_and_effective,
                    trust_anchor_count: m.trust_anchor_count,
                })
                .collect(),
            trust_anchor_count: report.trust_anchor_count,
            certificate_path_valid: report.certificate_path_valid,
            certificate_path_anchor_index: report.certificate_path_anchor_index,
            certificate_path_len: report.certificate_path_len,
            failure_reasons: report.failure_reasons,
            status_scope: TECHNICAL_EVIDENCE_ONLY.to_owned(),
        }
    }
}

fn is_qualified_signed(signed: &StoredSignedDocument) -> bool {
    signed.evidentiary_level == EVIDENTIARY_QUALIFIED
}

fn signed_pdf_timestamp_present(signed: &StoredSignedDocument) -> bool {
    signed.timestamp_token_der.is_some()
        || chancela_pades::validate_pdf_signature(&signed.signed_pdf_bytes)
            .map(|report| report.has_signature_timestamp)
            .unwrap_or(false)
}

impl DssEvidenceStatus {
    fn not_applicable() -> Self {
        Self {
            present: false,
            vri_count: 0,
            certificate_count: 0,
            ocsp_count: 0,
            crl_count: 0,
            certificate_sha256: Vec::new(),
            ocsp_sha256: Vec::new(),
            crl_sha256: Vec::new(),
            revocation_evidence_present: false,
            inspection_status: DSS_INSPECTION_NOT_APPLICABLE,
        }
    }

    fn unavailable() -> Self {
        Self {
            inspection_status: DSS_INSPECTION_UNAVAILABLE,
            ..Self::not_applicable()
        }
    }

    fn from_report(report: &chancela_pades::DssReport) -> Self {
        Self {
            present: report.present,
            vri_count: report.vri_count,
            certificate_count: report.certificate_count(),
            ocsp_count: report.ocsp_count(),
            crl_count: report.crl_count(),
            certificate_sha256: dss_hashes_hex(&report.certificate_hashes),
            ocsp_sha256: dss_hashes_hex(&report.ocsp_hashes),
            crl_sha256: dss_hashes_hex(&report.crl_hashes),
            revocation_evidence_present: report.has_revocation_evidence(),
            inspection_status: DSS_INSPECTION_INSPECTED,
        }
    }
}

fn dss_evidence_status(pdf_bytes: &[u8]) -> DssEvidenceStatus {
    match chancela_pades::inspect_dss(pdf_bytes) {
        Ok(report) => DssEvidenceStatus::from_report(&report),
        Err(_) => DssEvidenceStatus::unavailable(),
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

impl DocTimeStampEvidenceStatus {
    fn not_applicable() -> Self {
        Self {
            present: false,
            count: 0,
            token_sha256: Vec::new(),
            validations: Vec::new(),
            all_imprints_valid: false,
            inspection_status: DSS_INSPECTION_NOT_APPLICABLE,
        }
    }

    fn unavailable() -> Self {
        Self {
            inspection_status: DOC_TIMESTAMP_INSPECTION_UNAVAILABLE,
            ..Self::not_applicable()
        }
    }

    fn from_report(report: &chancela_pades::DocTimeStampReport) -> Self {
        Self {
            present: report.present,
            count: report.count,
            token_sha256: dss_hashes_hex(&report.token_hashes),
            validations: report
                .validations
                .iter()
                .map(DocTimeStampValidationEvidenceStatus::from_validation)
                .collect(),
            all_imprints_valid: report.all_imprints_valid(),
            inspection_status: DOC_TIMESTAMP_INSPECTION_INSPECTED,
        }
    }
}

impl DocTimeStampValidationEvidenceStatus {
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

impl RenewalPolicyEvidenceStatus {
    fn not_configured() -> Self {
        Self {
            status: RENEWAL_POLICY_NOT_CONFIGURED,
            action: RENEWAL_POLICY_MANUAL_REVIEW,
        }
    }
}

impl LocalTechnicalRenewalPlanEvidenceStatus {
    fn not_applicable() -> Self {
        Self::placeholder(RENEWAL_PLAN_NOT_APPLICABLE, RENEWAL_PLAN_ACTION_NONE)
    }

    fn unavailable() -> Self {
        Self::placeholder(RENEWAL_PLAN_UNAVAILABLE, RENEWAL_PLAN_ACTION_MANUAL_REVIEW)
    }

    fn placeholder(status: &'static str, next_action: &'static str) -> Self {
        Self {
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
}

fn renewal_plan_evidence_status(
    plan: &chancela_pades::LtvRenewalPlan,
) -> LocalTechnicalRenewalPlanEvidenceStatus {
    LocalTechnicalRenewalPlanEvidenceStatus {
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
        _ => RENEWAL_PLAN_ACTION_MANUAL_REVIEW,
    }
}

fn doc_timestamp_evidence_status(pdf_bytes: &[u8]) -> DocTimeStampEvidenceStatus {
    match chancela_pades::inspect_doc_timestamps(pdf_bytes) {
        Ok(report) => DocTimeStampEvidenceStatus::from_report(&report),
        Err(_) => DocTimeStampEvidenceStatus::unavailable(),
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

async fn ensure_act_exists(state: &AppState, act_id: ActId) -> Result<(), ApiError> {
    let acts = state.acts.read().await;
    acts.get(&act_id).ok_or(ApiError::NotFound).map(|_| ())
}

async fn sealed_act_audit_scope(state: &AppState, act_id: ActId) -> Result<String, ApiError> {
    let scope = act_audit_scope(state, act_id).await?;
    let acts = state.acts.read().await;
    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    if act.ata_number.is_none() {
        return Err(ApiError::Conflict(
            "o ato ainda não foi selado; convites de assinatura externa só acompanham atos selados"
                .to_owned(),
        ));
    }
    Ok(scope)
}

async fn act_audit_scope(state: &AppState, act_id: ActId) -> Result<String, ApiError> {
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;
    Ok(format!(
        "entity:{}/book:{}/act:{}",
        entity.id, act.book_id, act.id
    ))
}

async fn record_external_invite_event(
    state: &AppState,
    actor: &str,
    attestor: &CurrentAttestor,
    scope: &str,
    kind: &str,
    view: &(impl Serialize + ?Sized),
) -> Result<(), ApiError> {
    let payload = serde_json::to_vec(view)?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(&mut ledger, actor, scope, kind, None, &payload)?;
    state.persist_write_through(&mut ledger, 1, |_| Ok(()))?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

async fn find_live_external_invite_by_token(
    state: &AppState,
    token: String,
) -> Result<ExternalSignerInviteRecord, ApiError> {
    let token = required_trimmed(token, "token")?;
    let hash = sha256_hex(token.as_bytes());
    let now = OffsetDateTime::now_utc();
    let record = state
        .external_signer_invites
        .read()
        .await
        .values()
        .find(|record| record.token_sha256 == hash)
        .cloned()
        .ok_or(ApiError::NotFound)?;

    if record.revoked_at.is_some() || now >= record.expires_at {
        return Err(ApiError::NotFound);
    }
    Ok(record)
}

#[derive(Debug)]
struct ExternalSignedPdfUpload {
    signed_pdf_bytes: Vec<u8>,
    filename: Option<String>,
}

struct PreparedExternalSignedPdfEvidence {
    stored: StoredSignedDocument,
    signed_pdf_digest: String,
    timestamp_token: bool,
}

fn signed_pdf_upload_from_invite_response(
    decision: ExternalSignerInviteDecision,
    signed_pdf_base64: Option<String>,
    filename: Option<String>,
) -> Result<Option<ExternalSignedPdfUpload>, ApiError> {
    let Some(signed_pdf_base64) = signed_pdf_base64 else {
        return Ok(None);
    };
    if decision != ExternalSignerInviteDecision::Accept {
        return Err(ApiError::Unprocessable(
            "signed PDF uploads are accepted only with decision=accept".to_owned(),
        ));
    }
    Ok(Some(ExternalSignedPdfUpload {
        signed_pdf_bytes: decode_uploaded_signed_pdf_base64(&signed_pdf_base64)?,
        filename: optional_trimmed(filename),
    }))
}

fn decode_uploaded_signed_pdf_base64(value: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(value.trim())
        .map_err(|e| ApiError::Unprocessable(format!("invalid base64 signed PDF content: {e}")))
}

async fn prepare_external_signed_pdf_evidence(
    state: &AppState,
    act_id: ActId,
    signed_pdf: Vec<u8>,
) -> Result<PreparedExternalSignedPdfEvidence, ApiError> {
    if signed_pdf.is_empty() {
        return Err(ApiError::Unprocessable(
            "signed PDF upload is empty".to_owned(),
        ));
    }
    if signed_pdf.len() > OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "signed PDF upload is {} bytes; import accepts at most {} bytes",
            signed_pdf.len(),
            OFFICIAL_SIGNATURE_IMPORT_MAX_BYTES
        )));
    }

    let sealed = {
        let acts = state.acts.read().await;
        let act = acts.get(&act_id).ok_or(ApiError::NotFound)?;
        act.ata_number.is_some()
    };
    if !sealed {
        return Err(ApiError::Conflict(
            "o ato ainda não foi selado; o upload de PDF assinado externo é posterior ao selo"
                .to_owned(),
        ));
    }

    let unsigned = crate::documents::load_document(state, act_id)
        .await?
        .ok_or_else(|| {
            ApiError::Conflict("o ato selado não tem documento para assinar".to_owned())
        })?;

    if load_signed(state, act_id).await?.is_some() {
        return Err(ApiError::Conflict(
            "o ato já tem um artefacto de assinatura".to_owned(),
        ));
    }

    let report = validate_imported_signed_pdf(&signed_pdf)?;
    if !signed_pdf.starts_with(&unsigned.pdf_bytes) {
        return Err(ApiError::Conflict(
            "o PDF assinado não corresponde ao PDF selado deste ato".to_owned(),
        ));
    }

    let signed_pdf_digest = sha256_hex(&signed_pdf);
    let signed_at = OffsetDateTime::now_utc();
    let signing_time = report.cades.signing_time.unwrap_or(signed_at);
    let signer_cert_der = report.cades.signer_cert_der.clone();
    let timestamp_token = report.has_signature_timestamp;
    let stored = StoredSignedDocument {
        act_id,
        document_id: unsigned.id,
        signed_pdf_digest: signed_pdf_digest.clone(),
        signature_family: FAMILY_EXTERNAL_SIGNER_HANDOFF.to_owned(),
        evidentiary_level: EVIDENTIARY_EXTERNAL_SIGNED_PDF.to_owned(),
        trusted_list_status: None,
        signer_cert_subject: subject_dn(&signer_cert_der),
        signing_time,
        signed_at,
        signer_cert_der,
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        signed_pdf_bytes: signed_pdf,
    };

    Ok(PreparedExternalSignedPdfEvidence {
        stored,
        signed_pdf_digest,
        timestamp_token,
    })
}

async fn store_external_invite_signed_pdf_evidence(
    state: &AppState,
    attestor: &CurrentAttestor,
    record: &ExternalSignerInviteRecord,
    upload: ExternalSignedPdfUpload,
) -> Result<(), ApiError> {
    let signed_pdf_digest = sha256_hex(&upload.signed_pdf_bytes);
    if let Some(existing) = load_signed(state, record.act_id).await? {
        if existing.signature_family == FAMILY_EXTERNAL_SIGNER_HANDOFF
            && existing.signed_pdf_digest == signed_pdf_digest
        {
            return Ok(());
        }
        return Err(ApiError::Conflict(
            "o ato já tem um artefacto de assinatura".to_owned(),
        ));
    }

    let prepared =
        prepare_external_signed_pdf_evidence(state, record.act_id, upload.signed_pdf_bytes).await?;
    let document_id = prepared.stored.document_id.clone();
    let signed_pdf_digest = prepared.signed_pdf_digest.clone();
    let audit_scope = act_audit_scope(state, record.act_id).await?;
    let actor_name = format!("external-signer:{}", record.id);
    let filename = upload.filename;
    let legal_validation = official_import_legal_validation();
    let event_payload = json!({
        "act_id": record.act_id.to_string(),
        "document_id": document_id,
        "signed_pdf_digest": signed_pdf_digest,
        "family": FAMILY_EXTERNAL_SIGNER_HANDOFF,
        "evidentiary_level": EVIDENTIARY_EXTERNAL_SIGNED_PDF,
        "trusted_list_status": null,
        "profile": pades_profile(prepared.timestamp_token),
        "legal_validation": legal_validation,
        "validation": {
            "pades_cryptographic_validation": "valid",
            "byte_range_covers_whole_file_except_contents": true,
            "sealed_pdf_prefix_match": true,
            "trust_validation": "not_performed",
            "qualified_status_claimed": false
        },
        "source": {
            "kind": "external_signer_invite_response",
            "invite_id": record.id.to_string(),
            "filename": filename,
            "client_declared_metadata_authoritative": false
        },
        "status_scope": TECHNICAL_EVIDENCE_ONLY
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor_name,
            &audit_scope,
            "document.signed",
            None,
            &payload,
        )?;
        state.persist_write_through(&mut ledger, 1, |tx| {
            tx.upsert_signed_document(&prepared.stored)
        })?;
        state.attest_latest(attestor, &ledger).await;
    }
    state
        .signed_documents
        .write()
        .await
        .insert(record.act_id, prepared.stored);

    Ok(())
}

async fn external_invite_signed_artifact_status(
    state: &AppState,
    act_id: ActId,
) -> Result<Option<ExternalSignerInviteSignedArtifactPublicView>, ApiError> {
    let Some(signed) = load_signed(state, act_id).await? else {
        return Ok(None);
    };
    if signed.signature_family != FAMILY_EXTERNAL_SIGNER_HANDOFF {
        return Ok(None);
    }
    let timestamp_token = signed_pdf_timestamp_present(&signed);
    Ok(Some(ExternalSignerInviteSignedArtifactPublicView {
        family: signed.signature_family,
        evidentiary_level: signed.evidentiary_level,
        signed_pdf_digest: signed.signed_pdf_digest,
        timestamp_token,
        status_scope: TECHNICAL_EVIDENCE_ONLY,
        qualification_claimed: false,
        legal_status_claimed: false,
        notice: EXTERNAL_SIGNED_PDF_NOTICE,
    }))
}

async fn public_external_invite_view(
    state: &AppState,
    record: &ExternalSignerInviteRecord,
) -> Result<ExternalSignerInvitePublicView, ApiError> {
    let now = OffsetDateTime::now_utc();
    let context = external_invite_safe_context(state, record).await?;
    let signed_artifact = external_invite_signed_artifact_status(state, record.act_id).await?;

    Ok(ExternalSignerInvitePublicView {
        invite_id: record.id.to_string(),
        act: context.act,
        document: context.document,
        recipient_name: record.recipient_name.clone(),
        provider_hint: record.provider_hint.clone(),
        purpose: record.purpose.clone(),
        status: record.status_at(now),
        workflow: "tracking_only",
        created_at: rfc3339(record.created_at),
        expires_at: rfc3339(record.expires_at),
        responded_at: record.responded_at.map(rfc3339),
        signed_artifact,
        notice: EXTERNAL_INVITE_NOTICE,
    })
}

struct ExternalInviteSafeContext {
    act: ExternalSignerInviteActPublicView,
    document: Option<ExternalSignerInviteDocumentPublicView>,
}

async fn external_invite_safe_context(
    state: &AppState,
    record: &ExternalSignerInviteRecord,
) -> Result<ExternalInviteSafeContext, ApiError> {
    let entities = state.entities.read().await;
    let books = state.books.read().await;
    let acts = state.acts.read().await;
    let act = acts.get(&record.act_id).ok_or(ApiError::NotFound)?;
    if act.ata_number.is_none() {
        return Err(ApiError::NotFound);
    }
    let book = books.get(&act.book_id).ok_or(ApiError::NotFound)?;
    let entity = entities.get(&book.entity_id).ok_or(ApiError::NotFound)?;

    let act = ExternalSignerInviteActPublicView {
        id: record.act_id.to_string(),
        title: act.title.clone(),
        state: format!("{:?}", act.state),
        meeting_date: act.meeting_date.map(|d| d.to_string()),
        ata_number: act.ata_number,
        entity_name: entity.name.clone(),
        book_kind: format!("{:?}", book.kind),
    };
    drop(acts);
    drop(books);
    drop(entities);

    let document = crate::documents::load_document(state, record.act_id)
        .await?
        .map(|doc| ExternalSignerInviteDocumentPublicView::from_document(record.act_id, &doc));

    Ok(ExternalInviteSafeContext { act, document })
}

fn external_invite_working_copy_markdown(
    record: &ExternalSignerInviteRecord,
    act: &ExternalSignerInviteActPublicView,
    document: &ExternalSignerInviteDocumentPublicView,
) -> String {
    let now = OffsetDateTime::now_utc();
    let mut out = String::new();
    out.push_str("# EXTERNAL SIGNER WORKING COPY - NON-EVIDENTIARY\n\n");
    out.push_str(
        "This Markdown preview is available to the invite holder for review only. It is not the \
         preserved PDF/A, not a signed PDF, and not a qualified electronic signature.\n\n",
    );
    out.push_str("## Invite\n\n");
    out.push_str(&format!("- Invite ID: `{}`\n", record.id));
    out.push_str(&format!(
        "- Status: `{}`\n",
        external_invite_status_wire(record.status_at(now))
    ));
    out.push_str(&format!(
        "- Recipient: {}\n",
        markdown_text(&record.recipient_name)
    ));
    out.push_str(&format!("- Purpose: {}\n", markdown_text(&record.purpose)));
    if let Some(provider) = &record.provider_hint {
        out.push_str(&format!("- Reference: {}\n", markdown_text(provider)));
    }
    out.push_str(&format!("- Created at: `{}`\n", rfc3339(record.created_at)));
    out.push_str(&format!(
        "- Expires at: `{}`\n\n",
        rfc3339(record.expires_at)
    ));

    out.push_str("## Act metadata\n\n");
    out.push_str(&format!("- Act ID: `{}`\n", act.id));
    out.push_str(&format!("- Title: {}\n", markdown_text(&act.title)));
    out.push_str(&format!("- Entity: {}\n", markdown_text(&act.entity_name)));
    out.push_str(&format!(
        "- Book kind: `{}`\n",
        markdown_text(&act.book_kind)
    ));
    out.push_str(&format!("- State: `{}`\n", markdown_text(&act.state)));
    if let Some(number) = act.ata_number {
        out.push_str(&format!("- Ata number: `{number}`\n"));
    }
    if let Some(meeting_date) = &act.meeting_date {
        out.push_str(&format!(
            "- Meeting date: `{}`\n",
            markdown_text(meeting_date)
        ));
    }
    out.push('\n');

    out.push_str("## Document metadata\n\n");
    out.push_str(&format!("- Preserved document ID: `{}`\n", document.id));
    out.push_str(&format!(
        "- Template: `{}`\n",
        markdown_text(&document.template_id)
    ));
    out.push_str(&format!(
        "- Profile: `{}`\n",
        markdown_text(&document.profile)
    ));
    out.push_str(&format!(
        "- Preserved PDF digest: `{}`\n",
        document.pdf_digest
    ));
    out.push_str("- Canonical PDF: not exposed by this invite endpoint\n");
    out.push_str("- Qualified signature completion: not claimed by this acknowledgement flow\n");
    out
}

fn external_invite_status_wire(status: ExternalSignerInviteStatus) -> &'static str {
    match status {
        ExternalSignerInviteStatus::Pending => "pending",
        ExternalSignerInviteStatus::Accepted => "accepted",
        ExternalSignerInviteStatus::Declined => "declined",
        ExternalSignerInviteStatus::Expired => "expired",
        ExternalSignerInviteStatus::Revoked => "revoked",
    }
}

fn markdown_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('`', "\\`")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn required_trimmed(value: String, field: &'static str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ApiError::Unprocessable(format!("{field} is required")))
    } else {
        Ok(trimmed.to_owned())
    }
}

fn optional_trimmed(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn official_import_candidate_from_request(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<OfficialSignatureImportCandidate, ApiError> {
    if request_content_type_is_json(headers) {
        let req: OfficialSignatureImportRequest = serde_json::from_slice(body).map_err(|e| {
            ApiError::Unprocessable(format!(
                "invalid official signature import JSON envelope: {e}"
            ))
        })?;
        let signed_pdf_bytes = B64.decode(req.content_base64.trim()).map_err(|e| {
            ApiError::Unprocessable(format!("invalid base64 signed PDF content: {e}"))
        })?;
        return Ok(OfficialSignatureImportCandidate {
            signed_pdf_bytes,
            provider: optional_trimmed(req.provider),
            source: optional_trimmed(req.source),
            filename: optional_trimmed(req.filename),
            actor: optional_trimmed(req.actor),
        });
    }

    Ok(OfficialSignatureImportCandidate {
        signed_pdf_bytes: body.to_vec(),
        provider: None,
        source: None,
        filename: None,
        actor: None,
    })
}

fn request_content_type_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|base| base.trim().eq_ignore_ascii_case("application/json"))
}

fn validate_imported_signed_pdf(
    signed_pdf: &[u8],
) -> Result<chancela_pades::PdfSignatureReport, ApiError> {
    let report = chancela_pades::validate_pdf_signature(signed_pdf).map_err(|e| {
        ApiError::Unprocessable(format!(
            "uploaded PDF is not a valid signed PAdES artifact: {e}"
        ))
    })?;
    if !report.covers_whole_file_except_contents {
        return Err(ApiError::Unprocessable(
            "signed PDF ByteRange must cover the uploaded file except signature contents; later incremental updates are not accepted by this import slice"
                .to_owned(),
        ));
    }
    Ok(report)
}

fn official_import_legal_validation() -> OfficialSignatureLegalValidation {
    OfficialSignatureLegalValidation {
        pades_valid: true,
        byte_range_covers_whole_file: true,
        sealed_pdf_prefix_match: true,
        trust_validation: "not_performed",
        trust_validation_performed: false,
        qualified_status_claimed: false,
        legal_status_claimed: false,
    }
}

fn parse_rfc3339(value: &str, field: &'static str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| ApiError::Unprocessable(format!("{field} must be an RFC 3339 timestamp")))
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.trim().is_empty() && domain.contains('.') && !domain.trim().ends_with('.')
}

fn generate_invite_token() -> String {
    let mut bytes = [0_u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    format!("cxi_{}", crate::hex::hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    crate::hex::hex(&digest)
}

fn redact_invite_token(token: &str) -> String {
    if token.len() <= 18 {
        return "redacted".to_owned();
    }
    format!("{}...{}", &token[..8], &token[token.len() - 6..])
}

// --- CMD driver (DI: injected mock transport in tests, real HTTP in production) ---------------

/// A local newtype so an injected `Arc<dyn ScmdTransport + Send + Sync>` can be handed to
/// [`ScmdClient`] (which needs a concrete `T: ScmdTransport`). Delegates every call.
struct SharedScmdTransport(Arc<dyn ScmdTransport + Send + Sync>);

impl ScmdTransport for SharedScmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, chancela_cmd::CmdError> {
        self.0.call(action, soap_body)
    }
}

impl TslSource for RuntimeTslSource {
    fn fetch(&self) -> Result<Vec<u8>, TslError> {
        let bytes = if let Some(path) = self.location.path() {
            FileTslSource::new(path).fetch()?
        } else {
            let url = self
                .location
                .url()
                .expect("runtime TSL source has either path or URL");
            let client = reqwest::blocking::Client::builder()
                .timeout(StdDuration::from_secs(u64::from(self.timeout_seconds)))
                .build()?;
            client
                .get(url)
                .send()?
                .error_for_status()?
                .bytes()?
                .to_vec()
        };
        if bytes.len() as u64 > self.max_bytes {
            return Err(TslError::Structure(format!(
                "configured TSL source '{}' exceeded max_bytes ({} > {})",
                self.id,
                bytes.len(),
                self.max_bytes
            )));
        }
        Ok(bytes)
    }
}

struct BoundedTsaTransport {
    inner: chancela_tsa::HttpTsaTransport,
    provider_id: String,
    max_bytes: u64,
}

impl chancela_tsa::TsaTransport for BoundedTsaTransport {
    fn send(&self, der_req: &[u8]) -> Result<Vec<u8>, chancela_tsa::TsaError> {
        let bytes = chancela_tsa::TsaTransport::send(&self.inner, der_req)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(chancela_tsa::TsaError::Transport(format!(
                "TSA provider '{}' response exceeded max_bytes ({} > {})",
                self.provider_id,
                bytes.len(),
                self.max_bytes
            )));
        }
        Ok(bytes)
    }
}

/// Phase-1 driver: run `cmd_initiate` over the injected transport inline (tests, no network), or a
/// real `HttpScmdTransport` off the async runtime (production).
#[allow(clippy::too_many_arguments)]
async fn run_cmd_initiate(
    state: &AppState,
    cmd_cfg: &CmdConfig,
    tsl_source: Option<RuntimeTslSource>,
    phone: &str,
    pin: &str,
    doc_name: &str,
    signing_time: OffsetDateTime,
    prepared: &PreparedSignature,
) -> Result<CmdSignSession, ApiError> {
    let policy_factory = state.cmd_trust_policy.clone();
    if let Some(transport) = &state.cmd_transport {
        let client = ScmdClient::from_config(SharedScmdTransport(transport.clone()), cmd_cfg)
            .map_err(cmd_config_err)?;
        let mut policy = build_trust_policy(policy_factory.clone(), tsl_source.clone())?;
        let init = CmdInitiate {
            user_id: phone,
            pin,
            doc_name,
            signing_time,
        };
        cmd_initiate(&client, &init, prepared, Some(policy.as_mut())).map_err(map_signing_error)
    } else {
        // Production: the real SCMD/TSL calls block, so run them off the async worker.
        let cmd_cfg = cmd_cfg.clone();
        let prepared = prepared.clone();
        let phone = phone.to_owned();
        let pin = Zeroizing::new(pin.to_owned());
        let doc_name = doc_name.to_owned();
        let policy_factory = policy_factory.clone();
        let tsl_source = tsl_source.clone();
        tokio::task::spawn_blocking(move || {
            let transport = HttpScmdTransport::from_config(&cmd_cfg).map_err(cmd_config_err)?;
            let client = ScmdClient::from_config(transport, &cmd_cfg).map_err(cmd_config_err)?;
            let mut policy = build_trust_policy(policy_factory, tsl_source)?;
            let init = CmdInitiate {
                user_id: &phone,
                pin: &pin,
                doc_name: &doc_name,
                signing_time,
            };
            cmd_initiate(&client, &init, &prepared, Some(policy.as_mut()))
                .map_err(map_signing_error)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("cmd initiate task failed: {e}")))?
    }
}

/// Phase-2 driver: run `cmd_confirm` over the injected transport inline (tests), or a real
/// `HttpScmdTransport` off the async runtime (production).
async fn run_cmd_confirm(
    state: &AppState,
    cmd_cfg: &CmdConfig,
    session: &CmdSignSession,
    otp: &str,
) -> Result<Vec<u8>, ApiError> {
    if let Some(transport) = &state.cmd_transport {
        let client = ScmdClient::from_config(SharedScmdTransport(transport.clone()), cmd_cfg)
            .map_err(cmd_config_err)?;
        cmd_confirm(&client, session, otp).map_err(map_signing_error)
    } else {
        let cmd_cfg = cmd_cfg.clone();
        let session = session.clone();
        let otp = Zeroizing::new(otp.to_owned());
        tokio::task::spawn_blocking(move || {
            let transport = HttpScmdTransport::from_config(&cmd_cfg).map_err(cmd_config_err)?;
            let client = ScmdClient::from_config(transport, &cmd_cfg).map_err(cmd_config_err)?;
            cmd_confirm(&client, &session, &otp).map_err(map_signing_error)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("cmd confirm task failed: {e}")))?
    }
}

/// Build the trusted-list policy: the injected factory (tests), else a real `TslTrustPolicy` over
/// the selected configured TSL source (production). The qualified path MUST have a policy (ruling
/// 7), so no selected source is a client-actionable 422.
fn build_trust_policy(
    factory: Option<Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync>>,
    tsl_source: Option<RuntimeTslSource>,
) -> Result<Box<dyn TrustPolicy + Send>, ApiError> {
    if let Some(f) = factory {
        return Ok(f());
    }
    let source = tsl_source.ok_or_else(|| {
        ApiError::Unprocessable(
            "a assinatura qualificada requer uma Lista de Confiança (TSL) configurada".to_owned(),
        )
    })?;
    Ok(Box::new(TslTrustPolicy::new(source)))
}

/// Resolve the effective [`CmdConfig`]: environment secrets win (ApplicationId + BasicAuth +
/// AMA cert PEM); the non-secret settings selectors (`signing.cmd.env` / `.application_id`) fill
/// in when env is unset. A missing ApplicationId, or a prod config without the AMA cert, is a
/// client-actionable 422.
async fn resolve_cmd_config(state: &AppState) -> Result<CmdConfig, ApiError> {
    let cmd = { state.settings.read().await.signing.cmd.clone() };
    // Env-supplied secrets (never from the settings JSON).
    let env_cfg = CmdConfig::from_env().ok();
    let application_id = env_cfg
        .as_ref()
        .map(|c| c.application_id.clone())
        .or_else(|| cmd.application_id.clone())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "a Chave Móvel Digital não está configurada (falta o ApplicationId)".to_owned(),
            )
        })?;
    let env = match cmd.env {
        crate::settings::CmdEnvSetting::Preprod => CmdEnv::Preprod,
        crate::settings::CmdEnvSetting::Prod => CmdEnv::Prod,
    };
    let (basic_auth, ama_cert_pem) = env_cfg
        .map(|c| (c.basic_auth, c.ama_cert_pem))
        .unwrap_or((None, None));
    let cfg = CmdConfig {
        env,
        application_id,
        basic_auth,
        ama_cert_pem,
    };
    // Validate the field-encryptor is buildable (PROD without the AMA cert is refused here).
    cfg.field_encryptor()
        .map_err(|e| ApiError::Unprocessable(format!("configuração CMD inválida: {e}")))?;
    Ok(cfg)
}

// --- helpers ----------------------------------------------------------------------------------

struct FinalSignedPdf {
    bytes: Vec<u8>,
    timestamp_token_der: Option<Vec<u8>>,
    timestamp_trust_report_json: Option<String>,
    report: chancela_pades::PdfSignatureReport,
}

async fn finalize_signed_pdf(
    state: &AppState,
    signed_pdf: Vec<u8>,
    expected_signer_cert_der: &[u8],
) -> Result<FinalSignedPdf, ApiError> {
    let report = validate_signed_pdf(&signed_pdf, expected_signer_cert_der)?;
    let mut out = FinalSignedPdf {
        bytes: signed_pdf,
        timestamp_token_der: None,
        timestamp_trust_report_json: None,
        report,
    };

    let Some(tsa_provider) = configured_tsa_provider(state).await? else {
        return Ok(out);
    };
    let tsl_source = configured_tsl_source(state).await?;

    let pdf = std::mem::take(&mut out.bytes);
    let (stamped, timestamp, timestamp_trust_report_json) =
        tokio::task::spawn_blocking(move || {
            timestamp_pdf_with_trust_report(&pdf, tsa_provider, tsl_source)
                .map_err(map_timestamp_error)
        })
        .await
        .map_err(|e| ApiError::Internal(format!("timestamp task failed: {e}")))??;

    let report = validate_signed_pdf(&stamped, expected_signer_cert_der)?;
    if !report.has_signature_timestamp {
        return Err(ApiError::Internal(
            "timestamped signed PDF does not carry a signature timestamp".to_owned(),
        ));
    }
    out.bytes = stamped;
    out.timestamp_token_der = Some(timestamp.token_der);
    out.timestamp_trust_report_json = timestamp_trust_report_json;
    out.report = report;
    Ok(out)
}

fn timestamp_pdf_with_trust_report(
    signed_pdf: &[u8],
    tsa_provider: RuntimeTsaProvider,
    tsl_source: Option<RuntimeTslSource>,
) -> Result<(Vec<u8>, chancela_tsa::Timestamp, Option<String>), chancela_signing::SigningError> {
    if tsa_provider.digest.trim() != "sha256" {
        return Err(chancela_signing::SigningError::Timestamp(format!(
            "TSA provider '{}' requests digest {:?}; live timestamping currently supports sha256 only",
            tsa_provider.id, tsa_provider.digest
        )));
    }
    let tsa_url = tsa_provider.location.url().ok_or_else(|| {
        chancela_signing::SigningError::Timestamp(format!(
            "TSA provider '{}' is path-backed; live RFC 3161 timestamping requires an HTTP URL. Local TSA replay/signing is not implemented in this slice.",
            tsa_provider.id
        ))
    })?;
    let transport = chancela_tsa::HttpTsaTransport::with_timeout(
        tsa_url,
        StdDuration::from_secs(u64::from(tsa_provider.timeout_seconds)),
    )
    .map_err(|e| chancela_signing::SigningError::Timestamp(e.to_string()))?;
    let client = chancela_tsa::TsaClient::new(BoundedTsaTransport {
        inner: transport,
        provider_id: tsa_provider.id.clone(),
        max_bytes: tsa_provider.max_bytes,
    });
    let mut captured: Option<chancela_tsa::Timestamp> = None;
    let request_certificate = tsl_source.is_some();
    let stamped = add_signature_timestamp(signed_pdf, |sig_digest: &[u8; 32]| {
        let mut request = chancela_tsa::TimestampRequest::new(*sig_digest).with_generated_nonce();
        if let Some(policy) = tsa_provider
            .policy
            .as_deref()
            .map(str::trim)
            .filter(|policy| !policy.is_empty())
        {
            let oid = x509_cert::der::oid::ObjectIdentifier::new(policy).map_err(|e| {
                chancela_signing::SigningError::Timestamp(format!(
                    "TSA provider '{}' policy {:?} is not a valid OID: {e}",
                    tsa_provider.id, policy
                ))
            })?;
            request = request.with_policy(oid);
        }
        if !request_certificate {
            request = request.without_certificate();
        }
        let ts = client
            .stamp(&request)
            .map_err(|e| chancela_signing::SigningError::Timestamp(e.to_string()))?;
        captured = Some(ts.clone());
        Ok::<chancela_tsa::Timestamp, chancela_signing::SigningError>(ts)
    })
    .map_err(|e| chancela_signing::SigningError::Pades(e.to_string()))?;
    let timestamp = captured.ok_or_else(|| {
        chancela_signing::SigningError::Timestamp("timestamp callback did not run".to_owned())
    })?;
    let report_json = timestamp_trust_report_json(&timestamp, tsl_source);
    Ok((stamped, timestamp, report_json))
}

fn timestamp_trust_report_json(
    timestamp: &chancela_tsa::Timestamp,
    tsl_source: Option<RuntimeTslSource>,
) -> Option<String> {
    let tsa_cert = timestamp.tsa_certificate_der.as_deref()?;
    let mut tsl = TslClient::new(tsl_source?);
    let qtst = tsl.qtst_match_details(tsa_cert, timestamp.gen_time).ok()?;
    let report =
        timestamp_trust_evidence_status(timestamp, &qtst, &TimestampTrustPolicy::default());
    serde_json::to_string(&report).ok()
}

fn validate_signed_pdf(
    signed_pdf: &[u8],
    expected_signer_cert_der: &[u8],
) -> Result<chancela_pades::PdfSignatureReport, ApiError> {
    // Validate the produced PDF (SIG-24): the ByteRange must cover the whole file except
    // /Contents, and the embedded signer certificate must match the selected leaf certificate
    // (no substitution across providers).
    let report = chancela_pades::validate_pdf_signature(signed_pdf)
        .map_err(|e| ApiError::Internal(format!("signed PDF failed validation: {e}")))?;
    if !report.covers_whole_file_except_contents {
        return Err(ApiError::Internal(
            "signed PDF ByteRange does not cover the whole file".to_owned(),
        ));
    }
    if report.cades.signer_cert_der.as_slice() != expected_signer_cert_der {
        return Err(ApiError::Internal(
            "signed PDF signer certificate does not match the selected signing certificate"
                .to_owned(),
        ));
    }
    Ok(report)
}

fn validate_signed_pdf_with_incremental_updates(
    signed_pdf: &[u8],
    expected_signer_cert_der: &[u8],
) -> Result<chancela_pades::PdfSignatureReport, ApiError> {
    let report = chancela_pades::validate_pdf_signature(signed_pdf)
        .map_err(|e| ApiError::Internal(format!("signed PDF failed validation: {e}")))?;
    if !report.covers_signed_revision_except_contents {
        return Err(ApiError::Internal(
            "signed PDF ByteRange does not cover the signed revision".to_owned(),
        ));
    }
    if report.cades.signer_cert_der.as_slice() != expected_signer_cert_der {
        return Err(ApiError::Internal(
            "signed PDF signer certificate does not match the selected signing certificate"
                .to_owned(),
        ));
    }
    Ok(report)
}

async fn configured_tsa_provider(state: &AppState) -> Result<Option<RuntimeTsaProvider>, ApiError> {
    let selection = state.settings.read().await.signing.runtime_tsa_selection();
    if let Some(error) = selection.selection_error {
        return Err(ApiError::Unprocessable(format!(
            "configuração TSA inválida: {error}"
        )));
    }
    let Some(provider) = selection.selected else {
        return Ok(None);
    };
    if provider.location.url().is_none() {
        return Err(ApiError::Unprocessable(format!(
            "prestador TSA '{}' usa path local; a assinatura com carimbo temporal vivo requer um URL HTTP RFC 3161. Reproducao local de TSA nao esta implementada nesta fatia.",
            provider.id
        )));
    }
    if provider.digest.trim() != "sha256" {
        return Err(ApiError::Unprocessable(format!(
            "prestador TSA '{}' usa digest {:?}; a assinatura com carimbo temporal suporta apenas sha256",
            provider.id, provider.digest
        )));
    }
    Ok(Some(provider))
}

async fn configured_tsl_source(state: &AppState) -> Result<Option<RuntimeTslSource>, ApiError> {
    let selection = state.settings.read().await.signing.runtime_tsl_selection();
    if let Some(error) = selection.selection_error {
        return Err(ApiError::Unprocessable(format!(
            "configuração TSL inválida: {error}"
        )));
    }
    Ok(selection.selected)
}

fn map_timestamp_error(e: chancela_signing::SigningError) -> ApiError {
    ApiError::Unprocessable(format!("falha ao obter carimbo temporal qualificado: {e}"))
}

fn dss_attach_evidence_from_request(
    req: DssAttachRequest,
) -> Result<chancela_signing::DssEvidence, ApiError> {
    let evidence = chancela_signing::DssEvidence {
        certificates: decode_der_base64_list("certificates", req.certificates)?,
        ocsp_responses: decode_der_base64_list("ocsp_responses", req.ocsp_responses)?,
        crls: decode_der_base64_list("crls", req.crls)?,
    };
    if evidence.certificates.is_empty()
        && evidence.ocsp_responses.is_empty()
        && evidence.crls.is_empty()
    {
        return Err(ApiError::Unprocessable(
            "forneça pelo menos um certificado, resposta OCSP ou CRL em DER/base64".to_owned(),
        ));
    }
    Ok(evidence)
}

fn decode_single_der_base64(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::Unprocessable(format!("{field} is required")));
    }
    B64.decode(trimmed)
        .map_err(|_| ApiError::Unprocessable(format!("{field} não é base64 DER válido")))
}

fn decode_der_base64_list(field: &str, values: Vec<String>) -> Result<Vec<Vec<u8>>, ApiError> {
    values
        .into_iter()
        .enumerate()
        .map(|(idx, value)| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ApiError::Unprocessable(format!(
                    "{field}[{idx}] não pode estar vazio"
                )));
            }
            B64.decode(trimmed).map_err(|_| {
                ApiError::Unprocessable(format!("{field}[{idx}] não é base64 DER válido"))
            })
        })
        .collect()
}

fn map_dss_attach_error(e: chancela_signing::SigningError) -> ApiError {
    ApiError::Unprocessable(format!("falha ao anexar DSS/VRI local: {e}"))
}

fn map_local_pkcs12_signing_error(e: chancela_signing::SigningError) -> ApiError {
    match e {
        chancela_signing::SigningError::SoftCertificate(SoftCertificateError::WrongPassword) => {
            ApiError::Unprocessable("PKCS#12 password is incorrect".to_owned())
        }
        chancela_signing::SigningError::SoftCertificate(error) => {
            ApiError::Unprocessable(format!("invalid PKCS#12 signing material: {error}"))
        }
        chancela_signing::SigningError::Cades(msg)
        | chancela_signing::SigningError::Pades(msg)
        | chancela_signing::SigningError::Provider(msg) => {
            ApiError::Unprocessable(format!("local PKCS#12 signing failed: {msg}"))
        }
        other => ApiError::Unprocessable(format!("local PKCS#12 signing failed: {other}")),
    }
}

fn map_revocation_collect_error(e: chancela_signing::RevocationError) -> ApiError {
    ApiError::Unprocessable(format!(
        "falha ao recolher evidência de revogação CRL/OCSP: {e}"
    ))
}

fn collected_revocation_status(
    evidence: &chancela_signing::RevocationEvidence,
) -> CollectedRevocationEvidenceStatus {
    CollectedRevocationEvidenceStatus {
        validation_time: rfc3339(evidence.validation_time),
        discovered_ocsp_urls: evidence.discovered.ocsp_urls.clone(),
        discovered_crl_urls: evidence.discovered.crl_urls.clone(),
        ocsp_count: evidence.dss.ocsp_responses.len(),
        crl_count: evidence.dss.crls.len(),
        certificate_count: evidence.dss.certificates.len(),
        ocsp_sha256: evidence
            .ocsp_sources
            .iter()
            .map(|source| crate::hex::hex(&source.sha256))
            .collect(),
        crl_sha256: evidence
            .sources
            .iter()
            .map(|source| crate::hex::hex(&source.sha256))
            .collect(),
        source_scope: TECHNICAL_EVIDENCE_ONLY,
        legal_b_lt_claimed: false,
    }
}

/// Load the signed variant for an act (in-memory read model, falling back to the store on a miss).
async fn load_signed(
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

/// Load one pending session by id (in-memory, falling back to the store after a restart).
async fn load_pending(
    state: &AppState,
    session_id: &str,
) -> Result<Option<PendingCmdSession>, ApiError> {
    if let Some(p) = state
        .pending_signatures
        .read()
        .await
        .get(session_id)
        .cloned()
    {
        return Ok(Some(p));
    }
    if let Some(store) = &state.store {
        return store
            .pending_cmd_session(session_id)
            .map_err(|e| ApiError::Internal(format!("pending session store read failed: {e}")));
    }
    Ok(None)
}

/// Find any live pending session for an act (used by the status view).
async fn find_pending_for_act(state: &AppState, act_id: ActId) -> Option<PendingCmdSession> {
    state
        .pending_signatures
        .read()
        .await
        .values()
        .find(|p| p.act_id == act_id)
        .cloned()
}

/// Delete a pending session (durable + in-memory): consumed / expired / cancelled.
async fn consume_pending(state: &AppState, session_id: &str) {
    if let Some(store) = &state.store {
        let _ = store.persist(|tx| tx.delete_pending_cmd_session(session_id));
    }
    state.pending_signatures.write().await.remove(session_id);
}

/// Map a [`chancela_signing::SigningError`] to an [`ApiError`] with a client-safe status, never
/// echoing a secret (the error type carries none). Trust/SCMD failures are 502; an OTP rejection is
/// 422; a missing issuer / untrusted service is a clean, honest error.
fn map_signing_error(e: chancela_signing::SigningError) -> ApiError {
    use chancela_signing::SigningError as S;
    match e {
        S::UntrustedService { status } => ApiError::Unprocessable(format!(
            "o serviço de confiança do signatário não está ativo na Lista de Confiança ({})",
            status_label(status)
        )),
        S::MissingIssuerCertificate => ApiError::Unprocessable(
            "não foi possível resolver o emissor do certificado do signatário".to_owned(),
        ),
        // A provider failure is where an OTP rejection surfaces (ValidateOtp non-success). Report it
        // as 422 (client-actionable: wrong OTP / expired), without echoing the OTP.
        S::Provider(msg) => {
            ApiError::Unprocessable(format!("a Chave Móvel Digital recusou o pedido: {msg}"))
        }
        S::Cades(msg) | S::Pades(msg) => {
            ApiError::Internal(format!("falha ao montar a assinatura: {msg}"))
        }
        other => ApiError::Upstream(format!("falha no serviço de assinatura: {other}")),
    }
}

/// A CMD configuration failure (bad env/ApplicationId/AMA cert) is a client-actionable 422.
fn cmd_config_err(e: chancela_cmd::CmdError) -> ApiError {
    ApiError::Unprocessable(format!("configuração CMD inválida: {e}"))
}

/// The stable string label for a trusted-list status (used in payloads and views).
fn status_label(status: TrustedListStatus) -> String {
    match status {
        TrustedListStatus::Granted => "Granted".to_owned(),
        TrustedListStatus::Withdrawn => "Withdrawn".to_owned(),
        TrustedListStatus::Unknown => "Unknown".to_owned(),
        _ => "Unknown".to_owned(),
    }
}

/// Parse the subject DN from a certificate DER, or `None` if it does not parse.
fn subject_dn(der: &[u8]) -> Option<String> {
    use x509_cert::der::Decode;
    x509_cert::Certificate::from_der(der)
        .ok()
        .map(|c| c.tbs_certificate.subject.to_string())
}

/// A loose SCMD phone-format check (`+` country prefix, at least 9 digits). Not a full validator —
/// the SCMD service is authoritative — just enough to reject an obviously-wrong value early.
fn looks_like_scmd_phone(phone: &str) -> bool {
    let digits = phone.chars().filter(|c| c.is_ascii_digit()).count();
    phone.trim_start().starts_with('+') && digits >= 9
}

/// Mask the middle digits of a phone for display (keep the country/leading + last three).
fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len());
    }
    let keep_head = 5;
    let keep_tail = 3;
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if i < keep_head || i >= chars.len() - keep_tail || !c.is_ascii_digit() {
            out.push(*c);
        } else {
            out.push('•');
        }
    }
    out
}

/// A PDF `/M` date string (`D:YYYYMMDDHHMMSSZ`) for the signature dictionary.
fn pdf_time(t: OffsetDateTime) -> String {
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

/// RFC 3339 rendering of a timestamp (empty on the impossible format error).
fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::RuntimeTrustLocation;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "chancela-signature-test-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn runtime_tsa_provider(
        id: &str,
        location: RuntimeTrustLocation,
        digest: &str,
    ) -> RuntimeTsaProvider {
        RuntimeTsaProvider {
            id: id.to_owned(),
            name: id.to_owned(),
            location,
            policy: None,
            digest: digest.to_owned(),
            timeout_seconds: 30,
            max_bytes: 1024 * 1024,
            configured_index: Some(0),
            legacy: false,
        }
    }

    fn stored_signed_document(timestamp_token_der: Option<Vec<u8>>) -> StoredSignedDocument {
        let t = OffsetDateTime::from_unix_timestamp(0).unwrap();
        StoredSignedDocument {
            act_id: ActId(Uuid::nil()),
            document_id: "doc-1".to_owned(),
            signed_pdf_digest: "digest".to_owned(),
            signature_family: "ChaveMovelDigital".to_owned(),
            evidentiary_level: "Qualified".to_owned(),
            trusted_list_status: Some("Granted".to_owned()),
            signer_cert_subject: Some("CN=Signer".to_owned()),
            signing_time: t,
            signed_at: t,
            signer_cert_der: vec![1, 2, 3],
            timestamp_token_der,
            timestamp_trust_report_json: None,
            signed_pdf_bytes: b"%PDF".to_vec(),
        }
    }

    fn stored_signed_fixture(pdf_bytes: &[u8]) -> StoredSignedDocument {
        let mut doc = stored_signed_document(None);
        doc.signed_pdf_bytes = pdf_bytes.to_vec();
        doc
    }

    fn assert_local_renewal_plan_guardrails(plan: &LocalTechnicalRenewalPlanEvidenceStatus) {
        assert_eq!(plan.scope, LOCAL_TECHNICAL_EVIDENCE_ONLY);
        assert_eq!(plan.notice, RENEWAL_PLAN_NOTICE);
        assert!(!plan.production_long_term_profile_claimed);
        assert!(!plan.legal_ltv_claimed);
    }

    #[test]
    fn signature_evidence_status_classifies_unsigned_b_b_and_b_t() {
        let unsigned = signature_evidence_status(None);
        assert_eq!(unsigned.current_level, EVIDENCE_LEVEL_UNSIGNED);
        assert!(!unsigned.timestamp_evidence_present);
        assert!(!unsigned.dss_revocation_evidence_present);
        assert_eq!(unsigned.dss_revocation_evidence_status, "not_applicable");
        assert_eq!(unsigned.dss.inspection_status, "not_applicable");
        assert_eq!(unsigned.doc_timestamp.inspection_status, "not_applicable");
        assert!(!unsigned.doc_timestamp.present);
        assert!(!unsigned.local_b_lt_style_evidence_present);
        assert_eq!(unsigned.production_b_lt_status, "not_claimed");
        assert!(!unsigned.live_revocation_fetching);
        assert!(!unsigned.legal_b_lt_claimed);
        assert!(!unsigned.legal_b_lta_claimed);
        assert_eq!(unsigned.renewal_policy.status, "not_configured");
        assert_eq!(unsigned.renewal_policy.action, "manual_review");
        assert_local_renewal_plan_guardrails(&unsigned.local_technical_renewal_plan);
        assert_eq!(
            unsigned.local_technical_renewal_plan.status,
            RENEWAL_PLAN_NOT_APPLICABLE
        );
        assert_eq!(
            unsigned.local_technical_renewal_plan.next_action,
            RENEWAL_PLAN_ACTION_NONE
        );
        assert!(
            unsigned
                .local_technical_renewal_plan
                .missing_inputs
                .is_empty()
        );
        assert_eq!(
            unsigned.long_term_status,
            vec![
                LongTermEvidenceStatus::NotConfigured,
                LongTermEvidenceStatus::LtNotImplemented,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaNotImplemented,
            ]
        );

        let b_b_doc = stored_signed_document(None);
        let b_b = signature_evidence_status(Some(&b_b_doc));
        assert_eq!(b_b.current_level, EVIDENCE_LEVEL_B_B);
        assert!(!b_b.timestamp_evidence_present);
        assert_eq!(
            b_b.long_term_status,
            vec![
                LongTermEvidenceStatus::NotConfigured,
                LongTermEvidenceStatus::LtNotImplemented,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaNotImplemented,
            ]
        );
        assert_eq!(b_b.dss_revocation_evidence_status, "inspection_unavailable");
        assert_eq!(
            b_b.doc_timestamp.inspection_status,
            "inspection_unavailable"
        );
        assert_local_renewal_plan_guardrails(&b_b.local_technical_renewal_plan);
        assert_eq!(
            b_b.local_technical_renewal_plan.status,
            RENEWAL_PLAN_UNAVAILABLE
        );

        let b_t_doc = stored_signed_document(Some(b"timestamp-token".to_vec()));
        let b_t = signature_evidence_status(Some(&b_t_doc));
        assert_eq!(b_t.current_level, EVIDENCE_LEVEL_B_T);
        assert!(b_t.timestamp_evidence_present);
        assert_eq!(
            b_t.long_term_status,
            vec![
                LongTermEvidenceStatus::Timestamped,
                LongTermEvidenceStatus::LtNotImplemented,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaNotImplemented,
            ]
        );
        assert_eq!(b_t.dss_revocation_evidence_status, "inspection_unavailable");
        assert_eq!(b_t.timestamp_trust, None);
        assert!(!b_t.legal_b_lta_claimed);
        assert_eq!(b_t.renewal_policy.status, "not_configured");
        assert_eq!(b_t.renewal_policy.action, "manual_review");
        assert_local_renewal_plan_guardrails(&b_t.local_technical_renewal_plan);
        assert_eq!(
            b_t.local_technical_renewal_plan.status,
            RENEWAL_PLAN_UNAVAILABLE
        );
        assert_eq!(b_t.status_scope, TECHNICAL_EVIDENCE_ONLY);
    }

    #[test]
    fn signature_evidence_status_reports_b_b_fixture_renewal_plan() {
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bb-basic/input/bb-basic.pdf"
        );
        let doc = stored_signed_fixture(pdf);

        let status = signature_evidence_status(Some(&doc));

        assert_eq!(status.current_level, EVIDENCE_LEVEL_B_B);
        let plan = &status.local_technical_renewal_plan;
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan.status, RENEWAL_PLAN_AVAILABLE);
        assert!(!plan.signature_timestamp_present);
        assert!(!plan.dss_revocation_evidence_present);
        assert!(!plan.dss_validation_time_present);
        assert!(!plan.doc_timestamp_present);
        assert_eq!(
            plan.missing_inputs,
            vec![
                "signature_timestamp",
                "dss_revocation_evidence",
                "dss_validation_time",
                "document_timestamp"
            ]
        );
        assert_eq!(plan.next_action, "add_signature_timestamp");
        assert!(plan.has_local_evidence_gap);
        assert!(!plan.all_local_planning_inputs_present);
    }

    #[test]
    fn signature_evidence_status_keeps_timestamp_without_dss_as_lt_not_implemented() {
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-timestamped/input/bt-timestamped.pdf"
        );
        let doc = stored_signed_fixture(pdf);

        let status = signature_evidence_status(Some(&doc));

        assert_eq!(status.current_level, EVIDENCE_LEVEL_B_T);
        assert!(status.timestamp_evidence_present);
        assert!(!status.dss.present);
        assert_eq!(status.dss.inspection_status, DSS_INSPECTION_INSPECTED);
        assert_eq!(
            status.dss_revocation_evidence_status,
            DSS_REVOCATION_NOT_PRESENT
        );
        assert!(!status.dss_revocation_evidence_present);
        assert!(!status.local_b_lt_style_evidence_present);
        assert_eq!(
            status.long_term_status,
            vec![
                LongTermEvidenceStatus::Timestamped,
                LongTermEvidenceStatus::LtNotImplemented,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaNotImplemented,
            ]
        );
        assert!(!status.legal_b_lt_claimed);
        assert!(!status.legal_b_lta_claimed);
        let plan = &status.local_technical_renewal_plan;
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan.status, RENEWAL_PLAN_AVAILABLE);
        assert!(plan.signature_timestamp_present);
        assert!(!plan.dss_revocation_evidence_present);
        assert_eq!(
            plan.missing_inputs,
            vec![
                "dss_revocation_evidence",
                "dss_validation_time",
                "document_timestamp"
            ]
        );
        assert_eq!(plan.next_action, "embed_dss_revocation_evidence");
    }

    #[test]
    fn signature_evidence_status_reports_local_b_lt_for_dss_vri_evidence() {
        let pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-dss-local/input/bt-dss-local.pdf"
        );
        let doc = stored_signed_fixture(pdf);

        let status = signature_evidence_status(Some(&doc));

        assert_eq!(status.current_level, EVIDENCE_LEVEL_B_LT_LOCAL);
        assert!(status.timestamp_evidence_present);
        assert!(status.dss.present);
        assert!(status.dss.vri_count > 0);
        assert!(status.dss.ocsp_count > 0);
        assert!(status.dss.crl_count > 0);
        assert!(status.dss.revocation_evidence_present);
        assert_eq!(status.dss.inspection_status, DSS_INSPECTION_INSPECTED);
        assert_eq!(
            status.dss_revocation_evidence_status,
            DSS_REVOCATION_LOCAL_TECHNICAL_ONLY
        );
        assert!(status.local_b_lt_style_evidence_present);
        assert_eq!(
            status.long_term_status,
            vec![
                LongTermEvidenceStatus::Timestamped,
                LongTermEvidenceStatus::LtLocalTechnicalEvidence,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaNotImplemented,
            ]
        );
        assert_eq!(status.production_b_lt_status, PRODUCTION_B_LT_NOT_CLAIMED);
        assert_eq!(status.status_scope, TECHNICAL_EVIDENCE_ONLY);
        assert!(!status.legal_b_lt_claimed);
        assert!(!status.legal_b_lta_claimed);
        let plan = &status.local_technical_renewal_plan;
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan.status, RENEWAL_PLAN_AVAILABLE);
        assert!(plan.signature_timestamp_present);
        assert!(plan.dss_revocation_evidence_present);
        assert!(!plan.dss_validation_time_present);
        assert!(!plan.doc_timestamp_present);
        assert_eq!(
            plan.missing_inputs,
            vec!["dss_validation_time", "document_timestamp"]
        );
        assert_eq!(plan.next_action, "record_dss_validation_time");
    }

    #[test]
    fn doc_timestamp_status_reports_absent_and_valid_fixture_without_legal_b_lta_claim() {
        let no_dts_pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/bt-dss-local/input/bt-dss-local.pdf"
        );
        let no_dts = doc_timestamp_evidence_status(no_dts_pdf);
        assert_eq!(no_dts.inspection_status, "inspected_from_signed_pdf");
        assert!(!no_dts.present);
        assert_eq!(no_dts.count, 0);
        assert_eq!(no_dts.token_sha256, Vec::<String>::new());
        assert!(!no_dts.all_imprints_valid);

        let dts_pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/future-doctimestamp/input/future-doctimestamp.pdf"
        );
        let mut doc = stored_signed_document(Some(b"timestamp-token".to_vec()));
        doc.signed_pdf_bytes = dts_pdf.to_vec();
        let status = signature_evidence_status(Some(&doc));
        assert_eq!(status.current_level, EVIDENCE_LEVEL_B_LTA_LOCAL);
        assert_ne!(status.current_level, "B-LTA");
        assert!(!status.legal_b_lta_claimed);
        assert_eq!(status.renewal_policy.status, "not_configured");
        assert_eq!(status.renewal_policy.action, "manual_review");
        assert_eq!(
            status.doc_timestamp.inspection_status,
            "inspected_from_signed_pdf"
        );
        assert!(status.doc_timestamp.present);
        assert_eq!(status.doc_timestamp.count, 1);
        assert_eq!(status.doc_timestamp.token_sha256.len(), 1);
        assert_eq!(status.doc_timestamp.validations.len(), 1);
        assert_eq!(status.doc_timestamp.validations[0].status, "valid");
        assert_eq!(status.doc_timestamp.validations[0].failure_reason, None);
        assert!(status.doc_timestamp.all_imprints_valid);
        assert_eq!(
            status.long_term_status,
            vec![
                LongTermEvidenceStatus::Timestamped,
                LongTermEvidenceStatus::LtLocalTechnicalEvidence,
                LongTermEvidenceStatus::LtProductionNotClaimed,
                LongTermEvidenceStatus::LtaLocalTechnicalEvidence,
            ]
        );
        assert!(!status.legal_b_lt_claimed);
        assert!(!status.legal_b_lta_claimed);
        let plan = &status.local_technical_renewal_plan;
        assert_local_renewal_plan_guardrails(plan);
        assert_eq!(plan.status, RENEWAL_PLAN_AVAILABLE);
        assert!(plan.signature_timestamp_present);
        assert!(plan.dss_revocation_evidence_present);
        assert!(!plan.dss_validation_time_present);
        assert!(plan.doc_timestamp_present);
        assert!(plan.doc_timestamp_imprints_valid);
        assert_eq!(plan.missing_inputs, vec!["dss_validation_time"]);
        assert_eq!(plan.next_action, "record_dss_validation_time");
        assert!(plan.has_local_evidence_gap);
        assert!(!plan.all_local_planning_inputs_present);
    }

    #[test]
    fn doc_timestamp_status_reports_failed_imprint_fixture() {
        let mut dts_pdf = include_bytes!(
            "../../../docs/fixtures/validator-corpus/cases/future-doctimestamp/input/future-doctimestamp.pdf"
        )
        .to_vec();
        let version_byte = dts_pdf
            .iter()
            .position(|byte| *byte == b'7')
            .expect("PDF version digit");
        dts_pdf[version_byte] = b'6';

        let status = doc_timestamp_evidence_status(&dts_pdf);
        assert_eq!(status.inspection_status, "inspected_from_signed_pdf");
        assert!(status.present);
        assert_eq!(status.count, 1);
        assert_eq!(status.validations.len(), 1);
        assert_eq!(status.validations[0].status, "failed");
        assert_eq!(
            status.validations[0].failure_reason,
            Some("imprint_mismatch")
        );
        assert!(!status.all_imprints_valid);
    }

    #[test]
    fn signature_evidence_status_reloads_persisted_timestamp_trust_report() {
        let mut doc = stored_signed_document(Some(b"timestamp-token".to_vec()));
        doc.timestamp_trust_report_json = Some(
            serde_json::to_string(&TimestampTrustEvidenceStatus {
                decision: "rejected".to_owned(),
                policy_oid: "1.2.3.4".to_owned(),
                policy_oid_accepted: Some(false),
                tsa_certificate_embedded: true,
                embedded_certificate_count: 2,
                qtst_status: "unknown".to_owned(),
                qtst_authenticated: true,
                qtst_matches: vec![TimestampQtstMatchEvidenceStatus {
                    provider_name: "Provider".to_owned(),
                    service_name: "QTST".to_owned(),
                    granted_and_effective: false,
                    trust_anchor_count: 1,
                }],
                trust_anchor_count: 1,
                certificate_path_valid: false,
                certificate_path_anchor_index: None,
                certificate_path_len: None,
                failure_reasons: vec!["fixture diagnostic".to_owned()],
                status_scope: TECHNICAL_EVIDENCE_ONLY.to_owned(),
            })
            .unwrap(),
        );

        let status = signature_evidence_status(Some(&doc));
        let trust = status.timestamp_trust.expect("persisted report");
        assert_eq!(trust.policy_oid, "1.2.3.4");
        assert_eq!(trust.policy_oid_accepted, Some(false));
        assert_eq!(trust.qtst_matches[0].service_name, "QTST");
        assert_eq!(trust.status_scope, TECHNICAL_EVIDENCE_ONLY);
    }

    #[test]
    fn timestamp_trust_evidence_status_maps_validator_diagnostics_without_legal_claim() {
        let t = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let timestamp = chancela_tsa::Timestamp {
            token_der: b"token".to_vec(),
            gen_time: t,
            serial_number: vec![1],
            policy: "1.2.3.4".to_owned(),
            tsa_certificate_der: None,
            embedded_certificate_ders: vec![b"embedded".to_vec()],
        };
        let qtst = chancela_tsl::QtstMatchDetails {
            status: chancela_tsl::QualifiedStatus::Granted,
            matches: vec![chancela_tsl::QtstServiceMatch {
                provider_name: "Provider".to_owned(),
                service_name: "QTST".to_owned(),
                service_status: chancela_tsl::ServiceStatus::Granted,
                granted_and_effective: true,
                trust_anchor_ders: vec![b"anchor".to_vec()],
            }],
            trust_anchor_ders: vec![b"anchor".to_vec()],
            authenticated: true,
        };

        let status = timestamp_trust_evidence_status(
            &timestamp,
            &qtst,
            &TimestampTrustPolicy::require_one_of(["1.2.3.4"]),
        );

        assert_eq!(status.decision, "rejected");
        assert_eq!(status.policy_oid, "1.2.3.4");
        assert_eq!(status.policy_oid_accepted, Some(true));
        assert_eq!(status.qtst_status, "granted");
        assert!(status.qtst_authenticated);
        assert_eq!(status.qtst_matches.len(), 1);
        assert_eq!(status.qtst_matches[0].provider_name, "Provider");
        assert_eq!(status.trust_anchor_count, 1);
        assert!(!status.certificate_path_valid);
        assert!(status.failure_reasons.contains(
            &"timestamp token did not expose an embedded TSA signing certificate".to_owned()
        ));
        assert_eq!(status.status_scope, TECHNICAL_EVIDENCE_ONLY);
    }

    #[test]
    fn timestamp_path_backed_provider_fails_with_local_replay_blocker_before_network() {
        let provider = runtime_tsa_provider(
            "offline-default",
            RuntimeTrustLocation::Path("fixtures/tsa-response.der".to_owned()),
            "sha256",
        );

        let err = timestamp_pdf_with_trust_report(b"%PDF-1.7", provider, None)
            .expect_err("path-backed provider is not live-signing capable");

        assert!(
            err.to_string()
                .contains("Local TSA replay/signing is not implemented")
        );
    }

    #[test]
    fn timestamp_unsupported_digest_fails_before_network() {
        let provider = runtime_tsa_provider(
            "sha512-provider",
            RuntimeTrustLocation::Url("http://tsa.example.test".to_owned()),
            "sha512",
        );

        let err = timestamp_pdf_with_trust_report(b"%PDF-1.7", provider, None)
            .expect_err("unsupported digest is rejected locally");

        assert!(err.to_string().contains("supports sha256 only"));
    }

    #[test]
    fn trust_policy_file_backed_tsl_source_enforces_configured_max_bytes() {
        let tmp = TempDir::new();
        let path = tmp.0.join("oversize-tsl.xml");
        std::fs::write(&path, b"not actually parsed").expect("oversize TSL");
        let source = RuntimeTslSource {
            id: "local-small-bound".to_owned(),
            name: "Local small bound".to_owned(),
            location: RuntimeTrustLocation::Path(path.display().to_string()),
            timeout_seconds: 30,
            max_bytes: 1,
            configured_index: Some(0),
            legacy: false,
        };

        let mut policy = build_trust_policy(None, Some(source)).expect("policy builds");
        let err = policy
            .issuer_status(&[1, 2, 3], OffsetDateTime::from_unix_timestamp(0).unwrap())
            .expect_err("oversize local TSL fails closed");

        assert!(err.to_string().contains("exceeded max_bytes"));
    }

    #[test]
    fn external_invite_working_copy_markdown_is_non_evidentiary_and_redacted() {
        let t = OffsetDateTime::from_unix_timestamp(0).unwrap();
        let act_id = ActId(Uuid::nil());
        let record = ExternalSignerInviteRecord {
            id: Uuid::nil(),
            act_id,
            recipient_name: "Bruno Dias".to_owned(),
            recipient_email: "bruno@example.test".to_owned(),
            provider_hint: Some("manual-envelope".to_owned()),
            purpose: "Review only".to_owned(),
            token_sha256: "token-hash-must-not-render".to_owned(),
            token_hint: "cxi_secret_hint".to_owned(),
            created_at: t,
            created_by: "operator".to_owned(),
            expires_at: t + time::Duration::days(1),
            revoked_at: None,
            revoked_by: None,
            response: None,
            responded_at: None,
        };
        let act = ExternalSignerInviteActPublicView {
            id: act_id.to_string(),
            title: "Ata da AG anual".to_owned(),
            state: "Sealed".to_owned(),
            meeting_date: Some("2026-03-30".to_owned()),
            ata_number: Some(1),
            entity_name: "Encosto Estrategico, S.A.".to_owned(),
            book_kind: "AssembleiaGeral".to_owned(),
        };
        let document = ExternalSignerInviteDocumentPublicView {
            id: "doc-1".to_owned(),
            template_id: "csc-ata-ag/v1".to_owned(),
            profile: "application/pdf; profile=PDF/A-2u".to_owned(),
            pdf_digest: "0".repeat(64),
            artifact: ExternalSignerInviteArtifactPublicView {
                kind: EXTERNAL_INVITE_WORKING_COPY_KIND,
                method: "POST",
                path: EXTERNAL_INVITE_WORKING_COPY_PATH,
                content_type: EXTERNAL_INVITE_WORKING_COPY_CONTENT_TYPE,
                filename: "act-00000000-0000-0000-0000-000000000000-external-working-copy.md"
                    .to_owned(),
                notice: EXTERNAL_INVITE_WORKING_COPY_NOTICE,
            },
        };

        let markdown = external_invite_working_copy_markdown(&record, &act, &document);

        assert!(markdown.contains("EXTERNAL SIGNER WORKING COPY - NON-EVIDENTIARY"));
        assert!(markdown.contains("not a qualified electronic signature"));
        assert!(markdown.contains("Canonical PDF: not exposed"));
        assert!(markdown.contains("doc-1"));
        assert!(markdown.contains("Ata da AG anual"));
        assert!(!markdown.contains("bruno@example.test"));
        assert!(!markdown.contains("token-hash-must-not-render"));
        assert!(!markdown.contains("cxi_secret_hint"));
        assert!(!markdown.starts_with("%PDF-"));
    }
}
