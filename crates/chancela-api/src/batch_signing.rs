//! In-app **Cartão de Cidadão batch signing** (t67-e8, plan §2 Phase 4).
//!
//! A notary often seals a whole stack of acts in one sitting; asking for a fresh authentication per
//! document is hostile. `POST /v1/signature/cc/batch-sign` signs a set of already-sealed acts under
//! **one** signer authentication where the card allows it, driving the batch engine
//! [`chancela_signing::sign_pdf_batch`] (t67-e6) over a single co-located [`SmartcardProvider`]
//! (`SmartcardProvider`)(chancela_signing::SmartcardProvider). Each document is finalized, persisted,
//! and audited through the **exact** single-doc path ([`crate::signature::persist_cc_signed_pdf`]),
//! so a batch signature is byte-identical to a one-off CC signature.
//!
//! ## Honest authentication accounting (plan decision 3, §6)
//!
//! The card's qualified-signature key is `CKA_ALWAYS_AUTHENTICATE`, so the middleware performs one
//! login per document. With an **in-app PIN** the batch replays it programmatically to each login —
//! the signer types the PIN **once**, reported honestly as `auth_mode: "single_auth"`. **Without** a
//! PIN the protected-authentication path runs and the reader prompts per document — reported as
//! `"per_document_auth"`. The batch never claims a single PIN when the signer will be prompted per
//! document.
//!
//! ## Secret discipline (plan §6)
//!
//! The optional PIN is co-location-gated (a remote server 409s before any PIN is read), wrapped in a
//! [`Zeroizing`] buffer the instant it is read, threaded by reference into the blocking batch task,
//! and dropped/zeroized when the task ends. It is **never** persisted, logged, `Debug`-printed, or
//! placed in an audit record or an error/result body — a wrong/blocked PIN surfaces only its
//! PIN-free structured status.
//!
//! ## Scope
//!
//! Cartão de Cidadão only. The remote two-phase seam (CMD/CSC) is strictly one-digest-per-session
//! (t67-e6), so a true single-authentication remote fan-out is out of scope here; the soft-cert
//! PKCS#12 lane already unlocks its key once at load and has its own single-doc endpoint. Per-document
//! isolation: one document's failure never aborts the batch.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use chancela_authz::Permission;
use chancela_core::ActId;
use chancela_signing::AuthMode;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::{require_permission, scope_of_act};
use crate::error::ApiError;
use crate::signature::{
    CcBatchDocInput, SignerCapacityEvidence, cc_batch_doc_error_message, persist_cc_signed_pdf,
    resolve_cc_batch_doc, run_cc_batch_sign, signer_capacity_evidence_from_capacity,
    signer_capacity_evidence_json, status_label,
};

/// Upper bound on the number of acts a single batch may carry — bounds memory and card time; a
/// larger set must be split. Chosen generously for a sitting's worth of acts.
const MAX_CC_BATCH_ACTS: usize = 200;

/// Body of `POST /v1/signature/cc/batch-sign`.
///
/// **Secret discipline:** [`Self::pin`] is a transient in-app PIN (co-location-gated) — see the
/// module docs. `Deserialize`-only (no `Serialize`, no `Debug`) so the PIN cannot leak through this
/// DTO; the handler wraps it in [`Zeroizing`] immediately.
#[derive(Deserialize)]
pub struct CcBatchSignRequest {
    /// The acts to sign, in the order results are reported. Must be non-empty and free of duplicates.
    pub act_ids: Vec<Uuid>,
    /// The capacity in which the signer acts, applied to every document (optional, informational).
    #[serde(default)]
    pub capacity: Option<String>,
    /// The optional transient in-app Cartão de Cidadão PIN (co-location-gated). **Transient secret —
    /// consumed by the card logins, never persisted/logged/echoed.** Absent = protected-auth at the
    /// reader (one prompt per document).
    #[serde(default)]
    pub pin: Option<String>,
    /// Actor override for attribution when no session names one.
    #[serde(default)]
    pub actor: Option<String>,
}

/// Response of a batch signature — the honest authentication accounting plus every per-document
/// outcome, in the requested order. **Carries no secret** (no PIN anywhere).
#[derive(Serialize)]
pub struct CcBatchSignResponse {
    /// The signing family (`CartaoDeCidadao`).
    pub family: &'static str,
    /// How many times the signer authenticated to cover the whole batch: `"single_auth"` (one in-app
    /// PIN replayed) or `"per_document_auth"` (a reader prompt per document). Never overstated.
    pub auth_mode: &'static str,
    /// The number of documents that reached the card's signing operation.
    pub auth_events: usize,
    /// The signer issuer's trusted-list status resolved once for the batch, if a policy was consulted.
    pub trusted_list_status: Option<String>,
    /// The number of acts requested.
    pub requested: usize,
    /// The number of documents signed successfully.
    pub signed: usize,
    /// The number of documents that failed (precondition or signing).
    pub failed: usize,
    /// The declared signer-capacity evidence applied to the batch, when a capacity was supplied. This
    /// is request/operator evidence only, not SCAP/authority verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_capacity_evidence: Option<SignerCapacityEvidence>,
    /// The per-document outcomes, in the requested order.
    pub results: Vec<CcBatchDocResult>,
}

/// One document's outcome in a batch: either the produced signature facts or its PIN-free error.
#[derive(Serialize)]
pub struct CcBatchDocResult {
    /// The act this outcome corresponds to.
    pub act_id: String,
    /// `"signed"` or `"error"`.
    pub status: &'static str,
    /// The source unsigned document id (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// Lowercase-hex sha-256 of the signed PDF (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_pdf_digest: Option<String>,
    /// When the signature completed (RFC 3339; present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    /// Whether an RFC 3161 signature timestamp is present (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_token: Option<bool>,
    /// An honest, **PIN-free** failure message (present on error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CcBatchDocResult {
    fn error(act_id: &Uuid, message: String) -> Self {
        Self {
            act_id: act_id.to_string(),
            status: "error",
            document_id: None,
            signed_pdf_digest: None,
            signed_at: None,
            timestamp_token: None,
            error: Some(message),
        }
    }
}

fn auth_mode_label(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::SingleAuth => "single_auth",
        AuthMode::PerDocumentAuth => "per_document_auth",
        _ => "per_document_auth",
    }
}

/// `POST /v1/signature/cc/batch-sign` — sign a set of sealed acts with the Cartão de Cidadão under a
/// single authentication where the card allows it (t67-e8).
///
/// RBAC (`signing.perform`, scoped to each act's book) is checked for **every** act first: any denial
/// refuses the whole batch before the card is touched (a batch must never partially sign past an
/// authorization boundary). The co-location gate (CC-B) then applies; a remote server 409s. Each act
/// is resolved with the same preconditions as the single-doc path; a precondition failure is recorded
/// as that document's error and the batch continues. The trusted-list gate runs once over the shared
/// signer issuer and fails the whole batch closed if not `Granted`.
pub async fn sign_cc_batch(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CcBatchSignRequest>,
) -> Result<Json<CcBatchSignResponse>, ApiError> {
    if req.act_ids.is_empty() {
        return Err(ApiError::Unprocessable(
            "nenhum ato indicado para assinatura em lote".to_owned(),
        ));
    }
    if req.act_ids.len() > MAX_CC_BATCH_ACTS {
        return Err(ApiError::Unprocessable(format!(
            "a assinatura em lote aceita no máximo {MAX_CC_BATCH_ACTS} atos de cada vez"
        )));
    }
    // Reject duplicate acts up front: a duplicate would double-sign within one batch.
    {
        let mut seen = std::collections::HashSet::with_capacity(req.act_ids.len());
        if !req.act_ids.iter().all(|id| seen.insert(*id)) {
            return Err(ApiError::Unprocessable(
                "a lista de atos para assinatura em lote tem duplicados".to_owned(),
            ));
        }
    }

    // RBAC (t64-E3): a qualified signature is `signing.perform` scoped to the act's book — the SAME
    // gate as the single-doc endpoints, enforced for EVERY act before the card is touched. Checked
    // before the co-location gate so an unauthorized caller is refused identically everywhere.
    for id in &req.act_ids {
        let scope = scope_of_act(&state, ActId(*id)).await;
        require_permission(&state, &actor, Permission::SigningPerform, scope).await?;
    }
    let resolved_actor = actor.resolve(req.actor.as_deref().unwrap_or("api"));

    // Co-location gate (CC-B): a remote `chancela-server` can never reach the card in the client's
    // pocket. Refused there BEFORE any PIN is read.
    if !state.local_signing {
        return Err(ApiError::Conflict(
            "a assinatura com Cartão de Cidadão só está disponível na aplicação de secretária"
                .to_owned(),
        ));
    }

    // Transient in-app PIN: wrap the instant it is read, drop/zeroize when the batch task returns.
    let pin = req.pin.filter(|p| !p.is_empty()).map(Zeroizing::new);
    let pin_supplied = pin.is_some();

    // A fixed signing time (whole seconds) carried into every signature so the batch shares one
    // authoritative time.
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let capacity = req
        .capacity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let signer_capacity_evidence = signer_capacity_evidence_from_capacity(capacity.clone());
    let signer_capacity_evidence_json = signer_capacity_evidence_json(&signer_capacity_evidence)?;

    // Resolve every act (same preconditions as the single-doc path). Invalid acts become their own
    // error result; valid acts are prepared for the one crypto batch, remembering their input slot.
    let mut results: Vec<Option<CcBatchDocResult>> = (0..req.act_ids.len()).map(|_| None).collect();
    let mut prepared: Vec<CcBatchDocInput> = Vec::new();
    let mut prepared_slots: Vec<usize> = Vec::new();
    for (index, id) in req.act_ids.iter().enumerate() {
        match resolve_cc_batch_doc(
            &state,
            ActId(*id),
            signing_time,
            capacity.as_deref(),
            signer_capacity_evidence_json.clone(),
        )
        .await
        {
            Ok(input) => {
                prepared.push(input);
                prepared_slots.push(index);
            }
            Err(message) => {
                results[index] = Some(CcBatchDocResult::error(id, message));
            }
        }
    }

    // Nothing signable: return the per-document precondition errors without touching the card.
    if prepared.is_empty() {
        let results: Vec<CcBatchDocResult> = results.into_iter().flatten().collect();
        let failed = results.len();
        return Ok(Json(CcBatchSignResponse {
            family: "CartaoDeCidadao",
            auth_mode: if pin_supplied {
                "single_auth"
            } else {
                "per_document_auth"
            },
            auth_events: 0,
            trusted_list_status: None,
            requested: req.act_ids.len(),
            signed: 0,
            failed,
            signer_capacity_evidence,
            results,
        }));
    }

    // Snapshot the per-document persistence metadata BEFORE the batch consumes `prepared` (the PDF
    // bytes move into the blocking task). `prepared_slots`, this metadata, and the report's outcomes
    // are all in the same (input) order.
    let persist_meta: Vec<(ActId, Option<String>)> = prepared
        .iter()
        .map(|doc| (doc.act_id, doc.signer_capacity_evidence_json.clone()))
        .collect();

    let tsl_source = crate::signature::configured_tsl_source(&state).await?;
    let report = run_cc_batch_sign(&state, tsl_source, prepared, signing_time, pin).await?;

    let signing_cert_der = report.signing_cert_der.clone();
    let batch_trusted_list_status = report.trusted_list_status.map(status_label);

    // Finalize + persist each successful document through the shared single-doc path; map each
    // failure to a PIN-free per-document message. Outcomes are in `prepared` (input) order.
    for ((slot, (act_id, capacity_json)), outcome) in prepared_slots
        .iter()
        .zip(persist_meta)
        .zip(report.results.iter())
    {
        let id = &req.act_ids[*slot];
        let result = match &outcome.result {
            Ok(signed_pdf) => {
                let Some(cert_der) = signing_cert_der.as_deref() else {
                    // A produced signature implies the signer cert resolved; defend anyway.
                    results[*slot] = Some(CcBatchDocResult::error(
                        id,
                        "falha interna ao concluir a assinatura deste documento".to_owned(),
                    ));
                    continue;
                };
                match persist_cc_signed_pdf(
                    &state,
                    &attestor,
                    &resolved_actor,
                    act_id,
                    signed_pdf.clone(),
                    cert_der,
                    report.trusted_list_status,
                    signing_time,
                    capacity_json,
                )
                .await
                {
                    Ok(persisted) => CcBatchDocResult {
                        act_id: id.to_string(),
                        status: "signed",
                        document_id: Some(persisted.document_id),
                        signed_pdf_digest: Some(persisted.signed_pdf_digest),
                        signed_at: Some(crate::signature::rfc3339(persisted.signed_at)),
                        timestamp_token: Some(persisted.timestamp_token),
                        error: None,
                    },
                    Err(err) => CcBatchDocResult::error(id, api_error_message(err)),
                }
            }
            Err(err) => CcBatchDocResult::error(id, cc_batch_doc_error_message(err)),
        };
        results[*slot] = Some(result);
    }

    let results: Vec<CcBatchDocResult> = results.into_iter().flatten().collect();
    let signed = results.iter().filter(|r| r.status == "signed").count();
    let failed = results.len() - signed;

    Ok(Json(CcBatchSignResponse {
        family: "CartaoDeCidadao",
        auth_mode: auth_mode_label(report.auth_mode),
        auth_events: report.auth_events,
        trusted_list_status: batch_trusted_list_status,
        requested: req.act_ids.len(),
        signed,
        failed,
        signer_capacity_evidence,
        results,
    }))
}

/// A PIN-free message for a persistence failure surfaced as a per-document batch error. Internal
/// faults are summarised so no server internals leak into the result body.
fn api_error_message(err: ApiError) -> String {
    match err {
        ApiError::PinRejected { message, .. }
        | ApiError::Unprocessable(message)
        | ApiError::Conflict(message) => message,
        _ => "falha ao concluir a assinatura deste documento".to_owned(),
    }
}
