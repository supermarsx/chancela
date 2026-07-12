//! Long-term-validation (LTV) *execution* endpoints (t67-e9).
//!
//! These drive the real PAdES-B-LT / B-LTA execution pipeline landed by t67-e5
//! ([`chancela_signing::pipeline::execute_pdf_lta`] / [`renew_pdf_ltv`]) over an act's already
//! signed PDF, rather than the caller-supplied-evidence passthrough of the `dss/*` and
//! `archive-timestamp/*` endpoints in [`crate::signature`]:
//!
//! - `POST /v1/acts/{id}/signature/ltv/execute` — fetch validated revocation evidence for the signer
//!   chain, embed it as a `/DSS` + `/VRI` revision (LT), then append a `/DocTimeStamp` archive
//!   timestamp over that revision (LTA), in one incremental round.
//! - `POST /v1/acts/{id}/signature/ltv/renew` — one long-term-evidence renewal round over a PDF that
//!   already carries LT/LTA evidence: fetch fresh revocation material and append a second
//!   `/DSS` + `/DocTimeStamp` revision, preserving the earlier evidence.
//!
//! Honesty (plan §1.2 / §6): every response reports only evidence that was **actually embedded**. No
//! production or legal long-term-validation sufficiency is asserted — `legal_b_lt_claimed` /
//! `legal_b_lta_claimed` stay `false` and the status scope stays `technical_evidence_only`. The word
//! "valor probatório" is deliberately absent from every user-visible string (repo copy rule).
//!
//! RBAC: identical to the other signing/act-mutation endpoints — `signing.perform` scoped to the
//! act's book, checked before any I/O.

use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use chancela_authz::Permission;
use chancela_core::ActId;
use chancela_signing::RevocationEvidenceProvider;
use chancela_signing::pipeline::{execute_pdf_lta, renew_pdf_ltv};

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act};
use crate::error::ApiError;
use crate::signature::{
    CollectedRevocationEvidenceStatus, PRODUCTION_B_LT_NOT_CLAIMED, PRODUCTION_B_LTA_NOT_CLAIMED,
    SignatureEvidenceStatus, TECHNICAL_EVIDENCE_ONLY, act_audit_scope, build_bounded_tsa_client,
    collected_revocation_status, configured_tsa_provider, decode_single_der_base64, load_signed,
    map_ltv_execution_error, parse_rfc3339, sha256_hex, signature_evidence_status,
    validate_signed_pdf_with_incremental_updates,
};

/// The most bytes an LTV request envelope may carry (one issuer certificate as base64 DER).
pub(crate) const LTV_REQUEST_ENVELOPE_BYTES: usize = 256 * 1024;

/// Body of `POST /v1/acts/{id}/signature/ltv/execute` and `.../ltv/renew`.
///
/// Mirrors the `dss/collect-revocation` body: the stored signer certificate (from the signed
/// artifact) plus this caller-supplied issuer certificate drive validated CRL/OCSP collection before
/// any DSS/VRI attachment. The archive timestamp is produced by the configured runtime TSA provider.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LtvExecuteRequest {
    /// The signer's issuer (CA) certificate, DER encoded as base64. Required to resolve and validate
    /// the fetched revocation material against the correct issuer.
    #[serde(alias = "issuer_certificate_base64", alias = "issuer_cert_der_base64")]
    pub issuer_certificate: String,
    /// Optional RFC 3339 validation time (revocation freshness anchor). Defaults to now, whole seconds.
    #[serde(default)]
    pub validation_time: Option<String>,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a successful LTV execute / renew round.
#[derive(Serialize)]
pub struct LtvExecuteResponse {
    pub document_id: String,
    pub act_id: String,
    pub signed_pdf_digest: String,
    /// Whether an RFC 3161 signature timestamp is present on the underlying signature (B-T).
    pub timestamp_token: bool,
    /// Whether a `/DocTimeStamp` archive timestamp is now present (the "A" of B-LTA).
    pub archive_timestamp_present: bool,
    /// The observed embedded-evidence level after this round (a local technical marker, not a legal
    /// claim): typically `B-LTA-local`.
    pub evidentiary_level: &'static str,
    pub production_b_lt_status: &'static str,
    pub production_b_lta_status: &'static str,
    pub legal_b_lt_claimed: bool,
    pub legal_b_lta_claimed: bool,
    pub status_scope: &'static str,
    /// The full embedded-evidence status read back from the updated PDF (DSS + `/DocTimeStamp`).
    pub evidence: SignatureEvidenceStatus,
    /// The validated revocation evidence embedded by this round.
    pub revocation: CollectedRevocationEvidenceStatus,
}

/// `POST /v1/acts/{id}/signature/ltv/execute` — drive a full PAdES-B-LTA upgrade over the act's
/// signed PDF: fetch + embed validated revocation evidence (`/DSS`+`/VRI`, LT), then append a
/// `/DocTimeStamp` archive timestamp over it (LTA).
pub async fn execute_ltv(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<LtvExecuteRequest>,
) -> Result<Json<LtvExecuteResponse>, ApiError> {
    run_ltv_round(state, id, actor, attestor, req, LtvRound::Execute).await
}

/// `POST /v1/acts/{id}/signature/ltv/renew` — drive one long-term-evidence renewal round over the
/// act's signed PDF (which must already carry LT/LTA evidence): fetch fresh revocation material and
/// append a second `/DSS`+`/DocTimeStamp` revision, preserving the earlier evidence.
pub async fn renew_ltv(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<LtvExecuteRequest>,
) -> Result<Json<LtvExecuteResponse>, ApiError> {
    run_ltv_round(state, id, actor, attestor, req, LtvRound::Renew).await
}

/// Which pipeline entry point a round drives — an initial LT+LTA execution, or a renewal append.
#[derive(Clone, Copy)]
enum LtvRound {
    Execute,
    Renew,
}

impl LtvRound {
    fn event_kind(self) -> &'static str {
        match self {
            LtvRound::Execute => "document.signature.ltv_executed",
            LtvRound::Renew => "document.signature.ltv_renewed",
        }
    }
}

/// The shared body of both LTV rounds — identical plumbing (RBAC → load → re-validate → fetch
/// revocation + archive timestamp on a blocking worker → re-validate → persist + audit), differing
/// only in which pipeline function embeds the evidence.
async fn run_ltv_round(
    state: AppState,
    id: Uuid,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    req: LtvExecuteRequest,
    round: LtvRound,
) -> Result<Json<LtvExecuteResponse>, ApiError> {
    let act_id = ActId(id);
    let scope = scope_of_act(&state, act_id).await;
    require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    let actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    let mut stored = load_signed(&state, act_id)
        .await?
        .ok_or_else(|| ApiError::Conflict("o ato ainda não tem PDF assinado".to_owned()))?;

    // Re-validate the existing artifact (incremental updates allowed) before appending a new revision.
    validate_signed_pdf_with_incremental_updates(
        &stored.signed_pdf_bytes,
        &stored.signer_cert_der,
    )?;

    let issuer_cert_der = decode_single_der_base64("issuer_certificate", &req.issuer_certificate)?;
    let validation_time = match req.validation_time.as_deref() {
        Some(raw) => parse_rfc3339(raw, "validation_time")?,
        None => OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| OffsetDateTime::now_utc()),
    };

    // The archive timestamp of B-LTA needs a live RFC 3161 TSA; without one there is no "A" to add.
    let tsa_provider = configured_tsa_provider(&state).await?.ok_or_else(|| {
        ApiError::Unprocessable(
            "a execução LTV requer um prestador de carimbos temporais (TSA) configurado".to_owned(),
        )
    })?;

    let signer_cert_der = stored.signer_cert_der.clone();
    let input_pdf = stored.signed_pdf_bytes.clone();
    let (updated_pdf, collected) = tokio::task::spawn_blocking(move || {
        // Build the bounded TSA client and the real HTTP revocation provider inside the worker so
        // nothing crosses the thread boundary. The revocation provider fetches OCSP/CRL from the
        // signer certificate's own CDP/AIA URLs and validates issuer/responder trust + freshness
        // before anything is embedded (a certificate with no HTTP(S) revocation URI fails closed).
        let tsa_client = build_bounded_tsa_client(&tsa_provider)?;
        let revocation = RevocationEvidenceProvider::http();
        match round {
            LtvRound::Execute => {
                let execution = execute_pdf_lta(
                    &input_pdf,
                    &signer_cert_der,
                    &issuer_cert_der,
                    &revocation,
                    validation_time,
                    &tsa_client,
                )
                .map_err(map_ltv_execution_error)?;
                Ok::<_, ApiError>((execution.pdf, execution.revocation))
            }
            LtvRound::Renew => {
                let renewal = renew_pdf_ltv(
                    &input_pdf,
                    &signer_cert_der,
                    &issuer_cert_der,
                    &revocation,
                    validation_time,
                    &tsa_client,
                )
                .map_err(map_ltv_execution_error)?;
                Ok::<_, ApiError>((renewal.pdf, renewal.revocation))
            }
        }
    })
    .await
    .map_err(|e| ApiError::Internal(format!("LTV execution task failed: {e}")))??;

    // The updated artifact must still validate (over its signed revision) after the append.
    let report =
        validate_signed_pdf_with_incremental_updates(&updated_pdf, &stored.signer_cert_der)?;
    let signed_pdf_digest = sha256_hex(&updated_pdf);
    stored.signed_pdf_digest = signed_pdf_digest.clone();
    stored.signed_pdf_bytes = updated_pdf;

    let evidence_status = signature_evidence_status(Some(&stored));
    let revocation_status = collected_revocation_status(&collected);
    let archive_timestamp_present = evidence_status.doc_timestamp.present;
    let audit_scope = act_audit_scope(&state, act_id).await?;
    let event_payload = json!({
        "act_id": act_id.to_string(),
        "document_id": stored.document_id.clone(),
        "signed_pdf_digest": signed_pdf_digest.clone(),
        "evidentiary_level": evidence_status.current_level,
        "status_scope": TECHNICAL_EVIDENCE_ONLY,
        "production_b_lt_status": PRODUCTION_B_LT_NOT_CLAIMED,
        "production_b_lta_status": PRODUCTION_B_LTA_NOT_CLAIMED,
        "legal_b_lt_claimed": false,
        "legal_b_lta_claimed": false,
        "timestamp_token": report.has_signature_timestamp,
        "archive_timestamp_token": archive_timestamp_present,
        "dss": &evidence_status.dss,
        "doc_timestamp": &evidence_status.doc_timestamp,
        "revocation": &revocation_status,
    });
    let payload = serde_json::to_vec(&event_payload)?;
    {
        let mut ledger = state.ledger.write().await;
        crate::try_append_event(
            &mut ledger,
            &actor,
            &audit_scope,
            round.event_kind(),
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

    Ok(Json(LtvExecuteResponse {
        document_id: stored.document_id,
        act_id: act_id.to_string(),
        signed_pdf_digest,
        timestamp_token: evidence_status.timestamp_evidence_present,
        archive_timestamp_present,
        evidentiary_level: evidence_status.current_level,
        production_b_lt_status: PRODUCTION_B_LT_NOT_CLAIMED,
        production_b_lta_status: PRODUCTION_B_LTA_NOT_CLAIMED,
        legal_b_lt_claimed: false,
        legal_b_lta_claimed: false,
        status_scope: TECHNICAL_EVIDENCE_ONLY,
        evidence: evidence_status,
        revocation: revocation_status,
    }))
}
