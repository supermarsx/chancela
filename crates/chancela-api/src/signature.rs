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
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chancela_cmd::{CmdConfig, CmdEnv, HttpScmdTransport, ScmdClient, ScmdTransport};
use chancela_pades::{PreparedSignature, SignOptions, embed_signature, prepare_signature};
use chancela_signing::{
    CmdInitiate, CmdSignSession, TrustPolicy, TrustedListStatus, TslTrustPolicy, cmd_confirm,
    cmd_initiate,
};
use chancela_store::{PendingCmdSession, StoredSignedDocument};
use chancela_tsl::HttpTslSource;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zeroize::Zeroizing;

use chancela_authz::Permission;
use chancela_core::ActId;

use crate::AppState;
use crate::actor::CurrentActor;
use crate::actor::CurrentAttestor;
use crate::authz::{require_permission, scope_of_act};
use crate::error::ApiError;

/// The signing family this module produces (v1 is CMD-only; t57 ruling 2).
const FAMILY_CMD: &str = "ChaveMovelDigital";
/// The evidentiary level a successful CMD signature carries (SIG-01).
const EVIDENTIARY_QUALIFIED: &str = "Qualified";
/// The signed-PDF profile string bound into the `document.signed` event.
const PADES_PROFILE: &str = "application/pdf; profile=PAdES-B-B";
/// Pending-session lifetime, aligned to the SCMD OTP validity window.
const SESSION_TTL_SECS: i64 = 5 * 60;

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
    let tsl_url = { state.settings.read().await.signing.tsl_url.clone() };

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
        tsl_url,
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

    // Embed the CMS into the reserved placeholder → the final signed PDF.
    let signed_pdf = embed_signature(&prepared, &cms)
        .map_err(|e| ApiError::Internal(format!("failed to embed the CMS signature: {e}")))?;

    // Validate the produced PDF (SIG-24): the ByteRange must cover the whole file except /Contents,
    // and the embedded signer certificate must match the session's leaf (no substitution).
    let report = chancela_pades::validate_pdf_signature(&signed_pdf)
        .map_err(|e| ApiError::Internal(format!("signed PDF failed validation: {e}")))?;
    if !report.covers_whole_file_except_contents {
        return Err(ApiError::Internal(
            "signed PDF ByteRange does not cover the whole file".to_owned(),
        ));
    }
    if report.cades.signer_cert_der != session.signing_cert_der {
        return Err(ApiError::Internal(
            "signed PDF signer certificate does not match the pending session".to_owned(),
        ));
    }

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

    let digest: [u8; 32] = Sha256::digest(&signed_pdf).into();
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
        timestamp_token_der: None,
        signed_pdf_bytes: signed_pdf,
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
        "profile": PADES_PROFILE,
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
        timestamp_token: report.has_signature_timestamp,
        finalization: "finalizado_qualificado",
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
        return Ok(Json(SignatureStatusView {
            status: "signed",
            finalization: "finalizado_qualificado",
            require_qualified_for_seal: require_qualified,
            signed: Some(SignedInfo {
                family: signed.signature_family,
                evidentiary_level: signed.evidentiary_level,
                trusted_list_status: signed.trusted_list_status,
                signer_cert_subject: signed.signer_cert_subject,
                signing_time: rfc3339(signed.signing_time),
                signed_at: rfc3339(signed.signed_at),
                signed_pdf_digest: signed.signed_pdf_digest,
                timestamp_token: signed.timestamp_token_der.is_some(),
                download: format!("/v1/acts/{id}/document/signed"),
            }),
            pending: None,
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
            }));
        }
    }

    Ok(Json(SignatureStatusView {
        status: "unsigned",
        finalization: finalization_status(sealed, false, require_qualified),
        require_qualified_for_seal: require_qualified,
        signed: None,
        pending: None,
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

/// Derive the finalization status from the seal + signature state and the enforcement setting
/// (t57 ruling 6). `signed` means a validated `Qualified` signed variant exists.
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

// --- CMD driver (DI: injected mock transport in tests, real HTTP in production) ---------------

/// A local newtype so an injected `Arc<dyn ScmdTransport + Send + Sync>` can be handed to
/// [`ScmdClient`] (which needs a concrete `T: ScmdTransport`). Delegates every call.
struct SharedScmdTransport(Arc<dyn ScmdTransport + Send + Sync>);

impl ScmdTransport for SharedScmdTransport {
    fn call(&self, action: &str, soap_body: &str) -> Result<String, chancela_cmd::CmdError> {
        self.0.call(action, soap_body)
    }
}

/// Phase-1 driver: run `cmd_initiate` over the injected transport inline (tests, no network), or a
/// real `HttpScmdTransport` off the async runtime (production).
#[allow(clippy::too_many_arguments)]
async fn run_cmd_initiate(
    state: &AppState,
    cmd_cfg: &CmdConfig,
    tsl_url: Option<String>,
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
        let mut policy = build_trust_policy(policy_factory, tsl_url)?;
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
        tokio::task::spawn_blocking(move || {
            let transport = HttpScmdTransport::from_config(&cmd_cfg).map_err(cmd_config_err)?;
            let client = ScmdClient::from_config(transport, &cmd_cfg).map_err(cmd_config_err)?;
            let mut policy = build_trust_policy(policy_factory, tsl_url)?;
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
/// the configured `tsl_url` (production). The qualified path MUST have a policy (ruling 7), so a
/// missing TSL URL is a client-actionable 422.
fn build_trust_policy(
    factory: Option<Arc<dyn Fn() -> Box<dyn TrustPolicy + Send> + Send + Sync>>,
    tsl_url: Option<String>,
) -> Result<Box<dyn TrustPolicy + Send>, ApiError> {
    if let Some(f) = factory {
        return Ok(f());
    }
    let url = tsl_url.filter(|u| !u.trim().is_empty()).ok_or_else(|| {
        ApiError::Unprocessable(
            "a assinatura qualificada requer uma Lista de Confiança (TSL) configurada".to_owned(),
        )
    })?;
    Ok(Box::new(TslTrustPolicy::new(HttpTslSource::new(url))))
}

/// Resolve the effective [`CmdConfig`]: environment secrets win (ApplicationId + AMA cert PEM); the
/// non-secret settings selectors (`signing.cmd.env` / `.application_id`) fill in when env is unset.
/// A missing ApplicationId, or a prod config without the AMA cert, is a client-actionable 422.
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
    let ama_cert_pem = env_cfg.and_then(|c| c.ama_cert_pem);
    let cfg = CmdConfig {
        env,
        application_id,
        ama_cert_pem,
    };
    // Validate the field-encryptor is buildable (PROD without the AMA cert is refused here).
    cfg.field_encryptor()
        .map_err(|e| ApiError::Unprocessable(format!("configuração CMD inválida: {e}")))?;
    Ok(cfg)
}

// --- helpers ----------------------------------------------------------------------------------

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
