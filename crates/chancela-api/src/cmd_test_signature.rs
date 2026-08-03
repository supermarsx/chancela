//! **The Chave Móvel Digital production test signature** (t51-e3 §4.3).
//!
//! # Read this before changing anything here
//!
//! Every completed call to this module produces a **real, legally binding qualified electronic
//! signature**, made by a real citizen with their real Chave Móvel Digital, against AMA's real
//! production service. There is no rehearsal mode and there is no simulation. The word "test" in
//! the operator-facing label describes *what is signed* — a server-generated sheet that says, in
//! its own visible text, that it is a connectivity test and is not a business record — and never
//! the signature itself.
//!
//! That is not a design choice we could have avoided. CMD's protocol is
//! `GetCertificate → CCMovelSign → ValidateOtp`; `CCMovelSign` dispatches the SMS OTP and
//! `ValidateOtp` returns a signature over whatever digest was submitted. There is no ping, no
//! echo, no dry run. Anything that genuinely exercises the CMD signing flow **is** a signature.
//! The safe half of "does production CMD work?" is answered without cost by the preflight in
//! [`crate::provider_credentials_write::probe_cmd`]; this module is the other half, and it costs
//! a real signature every time.
//!
//! # The four things that keep this bounded
//!
//! 1. **The client never supplies the bytes.** There is no document in the request. The signed PDF
//!    is generated fresh, server-side, per request, and its own text states what it is. So the
//!    signature is real and qualified, and what it attests to is a sheet that describes itself.
//! 2. **The mock is unreachable, by construction.** This module never reads
//!    [`AppState::cmd_transport`] except to *refuse* when it is set, and it builds
//!    [`HttpScmdTransport`] unconditionally — there is no branch here that could yield a
//!    `MockScmdTransport`. A "successful" test against a mock would be the worst available
//!    outcome: it would tell an operator production CMD works when nothing was contacted.
//! 3. **The result can never count as a signature on an instrument.** The signed PDF is retained
//!    outside `instrument_signatures`, with no subject and no `slot_id`, and is written by this
//!    module's own file-backed retention rather than by
//!    `upsert_signed_termo_slot_signature`. `require_real_signatures` reads
//!    `instrument_signatures_for_subject`; a record that is not in that table cannot advance any
//!    book's open gate, and a test pins that.
//! 4. **Production only, fail closed.** Absent or incomplete credentials, a credential that does
//!    not resolve to production, or a server with nowhere to retain the result all refuse before
//!    AMA is contacted. Nothing here ever falls back to preprod, to the environment when a stored
//!    entry is incomplete, or to a mock.
//!
//!    Since t113 that refusal judges **the credential this test would actually use** — its own
//!    `env` selector, or the deployment default when it declares none (see
//!    [`crate::signature::resolve_cmd_env`]) — rather than the deployment setting alone. That is
//!    strictly tighter, not looser: an entry marked `prod` on a preprod-defaulted deployment used
//!    to be refused for the wrong reason, and a preprod credential is still refused for the right
//!    one.
//!
//! # Retention, and why refusing is the honest failure
//!
//! Destroying the evidence that a real qualified signature was produced is worse than keeping it,
//! so the signed PDF is retained on disk and the ledger records the operation twice — intent
//! before AMA is contacted, outcome after. A server with no data directory therefore **refuses
//! before signing**: producing a real qualified signature it could not retain would leave the
//! citizen's signature with no record of why it exists.
//!
//! Neither ledger event ever carries the PIN, the OTP, the phone in clear, or certificate
//! material.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chancela_authz::{Permission, Scope};
use chancela_cmd::{CmdConfig, CmdEnv, HttpScmdTransport, ScmdClient};
use chancela_core::{Block, DocumentModel, KvRow, Run};
use chancela_pades::validate::PdfSignatureCoverage;
use chancela_pades::{
    PreparedSignature, SignOptions, embed_signature, prepare_signature, validate_pdf_signature,
};
use chancela_signing::{CmdInitiate, CmdSignSession, cmd_confirm, cmd_initiate};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::AppState;
use crate::actor::{CurrentActor, CurrentAttestor};
use crate::authz::require_permission;
use crate::confirmation::{ConfirmationAction, ConfirmationProof, require_confirmation};
use crate::credential_resolve::ResolvedSource;
use crate::error::ApiError;

/// Stable Tier-2 [`ApiError::code`](crate::error::ApiError::code) values for this flow's refusals
/// (t112).
///
/// Every refusal below is written in **pt-PT prose**, and the flow renders the server's words
/// verbatim on purpose — the module refuses closed and NAMES what is wrong. That is right for a
/// pt-PT operator and wrong for the other thirteen locales, who read a Portuguese sentence in an
/// otherwise translated dialog. Attaching a code changes nothing an operator, a contract fixture or
/// a `body["error"]` assertion observes ([`ApiError::with_code`] is message-preserving by
/// construction); it just lets `apps/web/src/i18n/apiErrorFallback.ts` put a translated headline
/// above the server's own sentence instead of leaving it as the only thing on screen.
///
/// English, snake_case, never translated — the same rule as
/// [`crate::provider_probe_codes`], and the same rule the rest of the `code` vocabulary follows.
mod codes {
    /// The phone number is not in the SCMD `+351 XXXXXXXXX` shape. 422.
    pub const PHONE_INVALID: &str = "cmd_test_phone_invalid";
    /// The resolved CMD config is not production. 409 — there is no preprod rehearsal.
    pub const REQUIRES_PRODUCTION: &str = "cmd_test_requires_production";
    /// The deployment's CMD environment setting is preprod. 409.
    pub const ENVIRONMENT_PREPROD: &str = "cmd_test_environment_preprod";
    /// This instance has an injected (simulated) SCMD transport. 409.
    pub const SIMULATED_TRANSPORT: &str = "cmd_test_simulated_transport";
    /// Nowhere on disk to retain the signed PDF, so nothing is signed. 409.
    pub const NO_RETENTION_STORAGE: &str = "cmd_test_no_retention_storage";
    /// No usable CMD credential is configured at all. 409.
    pub const CREDENTIALS_MISSING: &str = "cmd_test_credentials_missing";
    /// The pinned entry is gone or disabled; the flow does not silently fail over. 409.
    pub const ENTRY_UNAVAILABLE: &str = "cmd_test_entry_unavailable";
    /// Only the actor who initiated may confirm. 403.
    pub const INITIATOR_ONLY: &str = "cmd_test_initiator_only";
    /// The single-use session aged out. 410 — a phase that expired, not a failure.
    pub const SESSION_EXPIRED: &str = "cmd_test_session_expired";
}
use crate::signature::{
    build_trust_policy, cmd_config_err, configured_tsl_source, finalize_signed_pdf,
    looks_like_scmd_phone, map_signing_error, mask_phone, pdf_time, resolve_cmd_candidates,
    rfc3339,
};

/// The ledger scope both audit events are recorded under. Deliberately **not** a book/act/entity
/// scope: a test signature belongs to no document chain and must never appear inside one.
const AUDIT_SCOPE: &str = "cmd_test_signature";

/// Recorded before AMA is contacted. If this cannot be durably appended, the test does not happen.
const INITIATE_REQUESTED_KIND: &str = "signature.cmd.test.initiate_requested";
/// Recorded after `CCMovelSign` returns — the OTP has been dispatched to a real device.
const INITIATED_KIND: &str = "signature.cmd.test.initiated";
/// Recorded before `ValidateOtp` — the point of no return for producing the signature.
const CONFIRM_REQUESTED_KIND: &str = "signature.cmd.test.confirm_requested";
/// Recorded after the qualified signature exists and has been retained.
const CONFIRMED_KIND: &str = "signature.cmd.test.confirmed";

/// How long an initiated test session stays confirmable. Mirrors the act path's CMD session TTL:
/// an OTP that has aged out must force a fresh, freshly-confirmed initiate.
const TEST_SESSION_TTL_SECS: i64 = 5 * 60;

/// Where retained test signatures live under the data directory.
const RETENTION_DIR: &str = "cmd-test-signatures";

/// The fixed marker every retained record and every response carries. It is a value rather than an
/// omitted disclaimer so no client can read the absence of a claim as a claim.
const LEGAL_EFFECT_NONE: &str = "none";

/// A test signature awaiting its OTP. Non-secret throughout: [`CmdSignSession`] is documented as
/// safe to persist between the two CMD requests (it holds no PIN and no OTP), and the prepared
/// revision is the unsigned document plus its ByteRange digest.
#[derive(Clone)]
pub struct PendingCmdTestSignature {
    session_id: String,
    /// The identity that initiated. Only this actor may confirm.
    actor: String,
    session: CmdSignSession,
    prepared: PreparedSignature,
    /// The stored credential entry the OTP was dispatched against, or `None` for the env fallback.
    /// Confirm resolves **this exact** entry and never re-resolves: a test that silently failed
    /// over to a different credential would have answered the wrong question, and here it would
    /// also have produced a real signature against a credential the operator did not choose.
    entry_id: Option<String>,
    masked_phone: String,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// The map of in-flight test sessions. Test signatures are deliberately **not** persisted across a
/// restart: an abandoned `CCMovelSign` produces nothing (the signature only exists once
/// `ValidateOtp` succeeds), so losing a pending session costs the operator one re-run and never
/// strands a real signature. The confirmed outcome, which does matter, is durable.
pub type PendingCmdTestSignatures = Arc<RwLock<HashMap<String, PendingCmdTestSignature>>>;

// --- Request / response DTOs -------------------------------------------------------------------

/// `POST /v1/signature/cmd/test-signature/initiate`.
///
/// The signer's phone and PIN are unavoidable — they are the citizen's own credential and CMD
/// cannot start without them. They are the **only** secret-bearing inputs, and there is
/// deliberately no document, no actor override of the RBAC subject, and no persistence flag.
#[derive(Deserialize)]
pub struct CmdTestSignatureInitiateRequest {
    /// The citizen's CMD mobile number, `+351 XXXXXXXXX`.
    pub phone: String,
    /// The CMD signature PIN. Held `Zeroizing`, consumed by `CCMovelSign`, never stored or logged.
    pub pin: String,
    /// Which stored credential entry to test. Omitted resolves the highest-priority enabled entry
    /// (or the environment fallback when nothing is stored) and reports which one was used.
    #[serde(default)]
    pub entry_id: Option<String>,
    /// Ledger attribution label, as elsewhere on the signing surface.
    #[serde(default)]
    pub actor: Option<String>,
    /// The T3 typed-phrase confirmation proof. Enforced server-side by
    /// [`require_confirmation`]; a client-side dialog is not a gate.
    #[serde(default)]
    pub confirmation: ConfirmationProof,
}

#[derive(Serialize)]
pub struct CmdTestSignatureInitiateResponse {
    pub session_id: String,
    pub status: &'static str,
    pub masked_phone: String,
    /// `stored_entry` or `environment` — an operator debugging this needs to know which.
    pub credential_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_label: Option<String>,
    pub environment: &'static str,
    pub expires_at: String,
    /// **The PIN-accepted checkpoint, stated as a value.** Always `true` here: reaching a successful
    /// initiate means `CCMovelSign` accepted the citizen's signing PIN at AMA and dispatched the OTP,
    /// so the operator can read "the PIN was accepted" as its own confirmed step rather than
    /// inferring it from the flow having advanced. A rejected PIN never produces this response — it
    /// is an `Err` (a `cmd_service_rejected` refusal), not an `Ok` with `pin_accepted: false`.
    ///
    /// It is a **value, not an omission**, for the same reason the other markers below are: a client
    /// must not read a silence as a claim. And it is not a free probe — reaching this checkpoint ran
    /// `CCMovelSign`, which is the first half of a real qualified signature (the module docs explain
    /// why there is no cheaper PIN check in this protocol).
    pub pin_accepted: bool,
    /// Fixed honest markers: an OTP has been dispatched to a real device, and nothing is signed yet.
    pub provider_contacted: bool,
    pub signer_authorization_requested: bool,
    pub document_signed: bool,
}

/// `POST /v1/signature/cmd/test-signature/confirm`.
#[derive(Deserialize)]
pub struct CmdTestSignatureConfirmRequest {
    pub session_id: String,
    /// The SMS OTP. Held `Zeroizing`, consumed by `ValidateOtp`, never stored or logged.
    pub otp: String,
    #[serde(default)]
    pub actor: Option<String>,
    /// The T3 typed-phrase proof again: confirm is the request that actually produces the
    /// signature, so it carries its own gate rather than trusting initiate's.
    #[serde(default)]
    pub confirmation: ConfirmationProof,
}

/// The outcome of a completed production test signature.
///
/// The `legal_*` / `counts_toward_*` fields are **values, not omissions**, for the same reason the
/// provider-probe DTO carries its honest negatives: a client must not be able to read a silence as
/// a claim. `document_signed` is `true` and `legal_effect` is `"none"` at the same time, and both
/// are true statements — a real qualified signature was made, over a sheet that is not a record.
#[derive(Serialize)]
pub struct CmdTestSignatureConfirmResponse {
    pub test_id: String,
    pub status: &'static str,
    pub provider_contacted: bool,
    pub document_signed: bool,
    /// Always `"none"`. This document is not an ata, not a termo, and not a business record.
    pub legal_effect: &'static str,
    /// Always `false`. Structurally guaranteed: the record is not in `instrument_signatures`.
    pub counts_toward_book_opening: bool,
    /// Always `false`. Same guarantee — no subject, no slot.
    pub counts_toward_act_signature: bool,
    pub signed_pdf_digest: String,
    pub signed_pdf_bytes: usize,
    pub signing_time: String,
    pub signed_at: String,
    pub masked_phone: String,
    pub credential_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_label: Option<String>,
    pub environment: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_list_status: Option<String>,
    pub timestamped: bool,
    /// Whether the signed PDF was written to the retention directory. Always `true` on success —
    /// a server that could not retain refuses before signing.
    pub retained: bool,
    /// What this product's own PAdES validator makes of the bytes it just produced. Present on
    /// every success, including the ones where the verdict is negative.
    pub self_validation: CmdTestSelfValidation,
}

/// What **this product's own PAdES validator** says about the signature this flow just produced.
///
/// An end-to-end test that stops at "AMA returned some bytes" proves less than it looks like it
/// proves: the bytes still have to be a PAdES signature that this product can itself verify over
/// the document it generated. So the finished PDF is fed straight back through
/// [`validate_pdf_signature`] — the same validator `POST /v1/documents/validate` uses — and the
/// verdict is reported as values.
///
/// **A negative verdict is reported, never hidden, and never turned into a failed request.** By the
/// time this runs the qualified signature already exists and has already been retained; converting
/// "my own validator did not accept it" into a 500 would destroy the operator's only view of a
/// genuinely interesting result. A test that says its own output did not verify is a successful
/// test with a bad answer, and the bad answer is the point.
#[derive(Serialize, Deserialize, Clone)]
pub struct CmdTestSelfValidation {
    /// Whether the embedded CMS verified against the `/ByteRange` digest recomputed from the file.
    pub signature_verifies: bool,
    /// Whether the signature covers the document **as rendered**. A verified CMS whose coverage is
    /// `altered_after_signing` or `malformed` is not a signature over what a reader would see, and
    /// this stays `false` for it — the gate `PdfSignatureCoverage::covers_rendered_document`
    /// exists to enforce.
    pub covers_rendered_document: bool,
    /// The coverage verdict as a stable token: `whole_document`,
    /// `ltv_augmented_signed_revision`, `altered_after_signing`, `malformed`, `unrecognised`
    /// (a variant this build does not know — the enum is `#[non_exhaustive]`), or `unavailable`
    /// (validation produced no verdict at all; see `error`).
    pub coverage: String,
    /// Whether the validator found an `id-aa-signatureTimeStampToken` unsigned attribute. Read from
    /// the finished bytes, so it is an independent confirmation of `timestamped` rather than a
    /// restatement of it.
    pub signature_timestamp_present: bool,
    /// Why the validator could not reach a verdict. Absent when it did — the presence of an
    /// explanation and the absence of one are both meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Run the product's own validator over the finished bytes. Infallible by construction: every
/// outcome, including "the validator refused these bytes", is a verdict worth reporting.
fn self_validate(signed_pdf: &[u8]) -> CmdTestSelfValidation {
    match validate_pdf_signature(signed_pdf) {
        Ok(report) => CmdTestSelfValidation {
            // `validate_pdf_signature` returns `Err` when the CMS does not verify, so an `Ok` is
            // the verification. Read the flag off the report anyway rather than hard-coding `true`:
            // the report is the authority on what it checked.
            signature_verifies: report.cades.attrs_ok,
            covers_rendered_document: report.coverage.covers_rendered_document(),
            coverage: match report.coverage {
                PdfSignatureCoverage::WholeDocument => "whole_document",
                PdfSignatureCoverage::LtvAugmentedSignedRevision => "ltv_augmented_signed_revision",
                PdfSignatureCoverage::AlteredAfterSigning => "altered_after_signing",
                PdfSignatureCoverage::Malformed => "malformed",
                // The enum is `#[non_exhaustive]`; a variant added later must not be silently
                // reported as one of the ones above. Naming it as unrecognised is the honest answer.
                _ => "unrecognised",
            }
            .to_owned(),
            signature_timestamp_present: report.has_signature_timestamp,
            error: None,
        },
        Err(e) => CmdTestSelfValidation {
            signature_verifies: false,
            covers_rendered_document: false,
            coverage: "unavailable".to_owned(),
            signature_timestamp_present: false,
            error: Some(e.to_string()),
        },
    }
}

/// The non-secret sidecar written beside each retained signed PDF.
#[derive(Serialize, Deserialize)]
struct RetainedTestSignature {
    test_id: String,
    actor: String,
    signed_pdf_digest: String,
    signing_time: String,
    signed_at: String,
    masked_phone: String,
    credential_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_label: Option<String>,
    environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_list_status: Option<String>,
    legal_effect: String,
    /// Retained alongside the bytes so the verdict survives with the evidence it is about. A reader
    /// of the retention directory can re-run the validator; keeping what it said at the time means
    /// they can also tell whether the answer has since changed.
    self_validation: CmdTestSelfValidation,
}

// --- Handlers ----------------------------------------------------------------------------------

/// `POST /v1/signature/cmd/test-signature/initiate` — phase 1.
///
/// Runs every gate, generates the test document, then `GetCertificate` → trusted-list gate →
/// `CCMovelSign`, which dispatches the OTP to the citizen's real device. Nothing is signed yet.
pub async fn initiate_cmd_test_signature(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CmdTestSignatureInitiateRequest>,
) -> Result<Json<CmdTestSignatureInitiateResponse>, ApiError> {
    // Configuring the provider and exercising a signing key are two different authorities, and this
    // action needs both — same rule `test_cc_bridge` applies to the Cartão de Cidadão probe.
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;
    // Composes with the RBAC gates above; never replaces them. T3 + typed phrase.
    require_confirmation(
        &state,
        &actor,
        ConfirmationAction::CmdTestSignature,
        &req.confirmation,
    )
    .await?;

    refuse_injected_transport(&state)?;
    let retention_dir = retention_dir(&state)?;

    let actor_label = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let phone = req.phone.trim().to_owned();
    if !looks_like_scmd_phone(&phone) {
        return Err(ApiError::Unprocessable(
            "número de telemóvel inválido para a Chave Móvel Digital (formato +351 XXXXXXXXX)"
                .to_owned(),
        )
        .with_code(codes::PHONE_INVALID));
    }
    // Held transiently: consumed by CCMovelSign below, then zeroized on drop. Never persisted.
    let pin = Zeroizing::new(req.pin);

    // Resolve through the SIGNING path's own candidate walk — stored entries first in priority
    // order, the environment only when nothing at all is stored — so the credential this test
    // exercises is the credential a real signature would use. An incomplete stored entry fails
    // closed here, naming the admin-panel fields that are missing.
    let (cfg, source) = resolve_pinned_candidate(&state, req.entry_id.as_deref()).await?;
    let (credential_source, entry_id, entry_label) = describe_source(&source);
    // Belt and braces over the settings check: the config the walk produced must itself be a
    // production config. A preprod config reaching this point would mean the resolver and the
    // settings disagree, and the correct response to that is to refuse.
    if !matches!(cfg.env, CmdEnv::Prod) {
        return Err(ApiError::Conflict(
            "a credencial que este teste usaria está resolvida para pré-produção e a assinatura de              teste só corre em produção. Escolha «Produção» no ambiente desta credencial ou, se a              credencial não indicar ambiente, mude o ambiente predefinido nas definições de              assinatura."
                .to_owned(),
        )
        .with_code(codes::ENVIRONMENT_PREPROD));
    }
    cfg.validate_http_transport().map_err(cmd_config_err)?;

    let tsl_source = configured_tsl_source(&state).await?;
    let signing_time = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let instance_name = {
        let settings = state.settings.read().await;
        settings
            .organization
            .name
            .clone()
            .unwrap_or_else(|| "Chancela".to_owned())
    };

    // The document is generated here, from server-held facts only. The request carries no bytes.
    let model = build_cmd_test_document(
        &instance_name,
        &actor_label,
        &rfc3339(signing_time),
        credential_source,
        entry_label.as_deref(),
    );
    let unsigned = chancela_doc::pdfa::write(&model)
        .map_err(|e| ApiError::Internal(format!("failed to render the CMD test document: {e}")))?;
    let opts = SignOptions {
        field_name: Some("Assinatura".to_owned()),
        signing_time: Some(pdf_time(signing_time)),
        reason: Some("Teste de ligação à Chave Móvel Digital (sem efeito jurídico)".to_owned()),
        location: None,
        contact_info: None,
    };
    let prepared = prepare_signature(&unsigned, &opts).map_err(|e| {
        ApiError::Internal(format!(
            "failed to prepare the CMD test document for signature: {e}"
        ))
    })?;

    // Intent, durably, BEFORE the provider is contacted. If the ledger cannot take it, the OTP is
    // never dispatched. The payload names the operation boundary and no secret.
    record_audit(
        &state,
        &actor_label,
        &attestor,
        INITIATE_REQUESTED_KIND,
        json!({
            "operation": "production_test_signature_initiate",
            "environment": "prod",
            "credential_source": credential_source,
            "entry_id": entry_id,
            "document_supplied_by_client": false,
            "document_is_business_record": false,
            "legal_effect": LEGAL_EFFECT_NONE,
            "qualified_signature_requested": true,
            "otp_dispatch_requested": true,
        }),
    )
    .await?;

    let session = run_test_initiate(
        &state,
        &cfg,
        tsl_source,
        &phone,
        &pin,
        signing_time,
        &prepared,
    )
    .await?;
    drop(pin);

    let session_id = Uuid::new_v4().to_string();
    let masked_phone = mask_phone(&phone);
    let expires_at = signing_time + time::Duration::seconds(TEST_SESSION_TTL_SECS);
    state.pending_cmd_test_signatures.write().await.insert(
        session_id.clone(),
        PendingCmdTestSignature {
            session_id: session_id.clone(),
            actor: actor_label.clone(),
            session,
            prepared,
            entry_id: entry_id.clone(),
            masked_phone: masked_phone.clone(),
            created_at: signing_time,
            expires_at,
        },
    );
    // The retention directory was resolved up front so a server with nowhere to keep the result
    // refuses before signing; create it now that a signature is genuinely in flight.
    std::fs::create_dir_all(&retention_dir).map_err(|e| {
        ApiError::Internal(format!(
            "failed to create the CMD test-signature retention directory: {e}"
        ))
    })?;

    record_audit(
        &state,
        &actor_label,
        &attestor,
        INITIATED_KIND,
        json!({
            "operation": "production_test_signature_initiate",
            "outcome": "otp_pending",
            "credential_source": credential_source,
            "entry_id": entry_id,
            "pin_accepted": true,
            "otp_dispatched": true,
            "document_signed": false,
        }),
    )
    .await?;

    Ok(Json(CmdTestSignatureInitiateResponse {
        session_id,
        status: "otp_pending",
        masked_phone,
        credential_source,
        entry_id,
        entry_label,
        environment: "prod",
        expires_at: rfc3339(expires_at),
        pin_accepted: true,
        provider_contacted: true,
        signer_authorization_requested: true,
        document_signed: false,
    }))
}

/// `POST /v1/signature/cmd/test-signature/confirm` — phase 2, and the point at which a real
/// qualified signature comes into existence.
pub async fn confirm_cmd_test_signature(
    State(state): State<AppState>,
    actor: CurrentActor,
    attestor: CurrentAttestor,
    Json(req): Json<CmdTestSignatureConfirmRequest>,
) -> Result<Json<CmdTestSignatureConfirmResponse>, ApiError> {
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
    require_permission(&state, &actor, Permission::SigningPerform, Scope::Global).await?;
    require_confirmation(
        &state,
        &actor,
        ConfirmationAction::CmdTestSignature,
        &req.confirmation,
    )
    .await?;

    refuse_injected_transport(&state)?;
    let retention_dir = retention_dir(&state)?;

    let actor_label = actor.resolve(req.actor.as_deref().unwrap_or("api"));
    let otp = Zeroizing::new(req.otp);

    let pending = {
        let sessions = state.pending_cmd_test_signatures.read().await;
        sessions
            .get(&req.session_id)
            .cloned()
            .ok_or(ApiError::NotFound)?
    };
    if pending.actor != actor_label {
        return Err(ApiError::Forbidden(
            "apenas quem iniciou a assinatura de teste a pode confirmar".to_owned(),
        )
        .with_code(codes::INITIATOR_ONLY));
    }
    if OffsetDateTime::now_utc() >= pending.expires_at {
        state
            .pending_cmd_test_signatures
            .write()
            .await
            .remove(&pending.session_id);
        return Err(ApiError::Gone(
            "a sessão de assinatura de teste expirou; inicie uma nova".to_owned(),
        )
        .with_code(codes::SESSION_EXPIRED));
    }

    // Pin the EXACT entry the OTP was dispatched against. Never re-resolve: the citizen's OTP was
    // issued under one ApplicationId, and submitting it under another would both fail and, worse,
    // silently answer a question about a credential nobody chose to test.
    let (cfg, source) = resolve_pinned_candidate(&state, pending.entry_id.as_deref()).await?;
    let (credential_source, entry_id, entry_label) = describe_source(&source);
    // A DIFFERENT fact from the initiate-phase refusal, and so a different code: initiate refuses
    // because the operator picked a preprod credential, which they can fix by choosing another.
    // Reaching here means the same pinned credential resolved to production at initiate and does
    // not now — the configuration moved under a live session, with an OTP already dispatched. The
    // OTP is spent either way; what must not happen is signing under an environment nobody agreed
    // to, so this refuses too.
    if !matches!(cfg.env, CmdEnv::Prod) {
        return Err(ApiError::Conflict(
            "a assinatura de teste só corre contra o ambiente de produção da Chave Móvel Digital"
                .to_owned(),
        )
        .with_code(codes::REQUIRES_PRODUCTION));
    }
    cfg.validate_http_transport().map_err(cmd_config_err)?;

    record_audit(
        &state,
        &actor_label,
        &attestor,
        CONFIRM_REQUESTED_KIND,
        json!({
            "operation": "production_test_signature_confirm",
            "environment": "prod",
            "credential_source": credential_source,
            "entry_id": entry_id,
            "qualified_signature_requested": true,
            "document_is_business_record": false,
            "legal_effect": LEGAL_EFFECT_NONE,
        }),
    )
    .await?;

    // ValidateOtp → the detached CMS. From here a real qualified signature exists.
    let cms = run_test_confirm(&cfg, &pending.session, &otp).await?;
    drop(otp);
    let signed_pdf = embed_signature(&pending.prepared, &cms)
        .map_err(|e| ApiError::Internal(format!("failed to embed the CMS signature: {e}")))?;
    let final_pdf =
        finalize_signed_pdf(&state, signed_pdf, &pending.session.signing_cert_der).await?;

    let digest: [u8; 32] = Sha256::digest(&final_pdf.bytes).into();
    let signed_pdf_digest = crate::hex::hex(&digest);
    let signed_at = OffsetDateTime::now_utc();
    let trusted_list_status = pending
        .session
        .trusted_list_status
        .map(|status| format!("{status:?}"));
    let test_id = Uuid::new_v4().to_string();
    // Close the loop before anything is written or reported: the point of an end-to-end test is
    // that the chain holds all the way back, and a signature this product cannot itself verify is a
    // result the operator needs to see rather than one the server should swallow.
    let self_validation = self_validate(&final_pdf.bytes);

    // Retain OUTSIDE `instrument_signatures`: this record has no subject and no slot_id, and is not
    // written by the instrument-signature writer, so `require_real_signatures` — which reads
    // `instrument_signatures_for_subject` — cannot see it. That is the structural guarantee, not a
    // convention: there is no table row for it to find.
    let record = RetainedTestSignature {
        test_id: test_id.clone(),
        actor: actor_label.clone(),
        signed_pdf_digest: signed_pdf_digest.clone(),
        signing_time: rfc3339(pending.created_at),
        signed_at: rfc3339(signed_at),
        masked_phone: pending.masked_phone.clone(),
        credential_source: credential_source.to_owned(),
        entry_id: entry_id.clone(),
        entry_label: entry_label.clone(),
        environment: "prod".to_owned(),
        trusted_list_status: trusted_list_status.clone(),
        legal_effect: LEGAL_EFFECT_NONE.to_owned(),
        self_validation: self_validation.clone(),
    };
    let signed_pdf_bytes = final_pdf.bytes.len();
    retain_test_signature(&retention_dir, &record, &final_pdf.bytes)?;

    state
        .pending_cmd_test_signatures
        .write()
        .await
        .remove(&pending.session_id);

    record_audit(
        &state,
        &actor_label,
        &attestor,
        CONFIRMED_KIND,
        json!({
            "operation": "production_test_signature_confirm",
            "outcome": "signed",
            "test_id": test_id,
            "signed_pdf_digest": signed_pdf_digest,
            "credential_source": credential_source,
            "entry_id": entry_id,
            "environment": "prod",
            "trusted_list_status": trusted_list_status,
            "document_signed": true,
            "document_is_business_record": false,
            "legal_effect": LEGAL_EFFECT_NONE,
            "counts_toward_book_opening": false,
            "counts_toward_act_signature": false,
            "retained": true,
            "self_validation_signature_verifies": self_validation.signature_verifies,
            "self_validation_covers_rendered_document": self_validation.covers_rendered_document,
            "self_validation_coverage": self_validation.coverage.clone(),
        }),
    )
    .await?;

    Ok(Json(CmdTestSignatureConfirmResponse {
        test_id,
        status: "signed",
        provider_contacted: true,
        document_signed: true,
        legal_effect: LEGAL_EFFECT_NONE,
        counts_toward_book_opening: false,
        counts_toward_act_signature: false,
        signed_pdf_digest,
        signed_pdf_bytes,
        signing_time: rfc3339(pending.created_at),
        signed_at: rfc3339(signed_at),
        masked_phone: pending.masked_phone,
        credential_source,
        entry_id,
        entry_label,
        environment: "prod",
        trusted_list_status,
        timestamped: final_pdf.timestamp_token_der.is_some(),
        retained: true,
        self_validation,
    }))
}

/// `GET /v1/signature/cmd/test-signature/{test_id}/document` — the retained signed PDF.
///
/// Read-only, `signing.configure`-gated. The bytes are a genuine qualified signature over a
/// document that says of itself that it has no legal effect as a business record.
pub async fn get_cmd_test_signature_document(
    State(state): State<AppState>,
    Path(test_id): Path<String>,
    actor: CurrentActor,
) -> Result<Response, ApiError> {
    require_permission(&state, &actor, Permission::SigningConfigure, Scope::Global).await?;
    let dir = retention_dir(&state)?;
    // The id is a server-minted UUID; reject anything else rather than letting it reach the path.
    let test_id = Uuid::parse_str(&test_id)
        .map_err(|_| ApiError::NotFound)?
        .to_string();
    let bytes =
        std::fs::read(dir.join(format!("{test_id}.pdf"))).map_err(|_| ApiError::NotFound)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pdf".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"cmd-teste-{test_id}.pdf\""),
            ),
        ],
        Body::from(bytes),
    )
        .into_response())
}

// --- Gates -------------------------------------------------------------------------------------

/// **The mock refusal.** [`AppState::cmd_transport`] is a test/DI seam set only by in-process Rust
/// test code; production never populates it. This handler nevertheless refuses outright when it is
/// set, because a test signature that "succeeded" against a canned SOAP fixture would report that
/// production CMD works while nothing was contacted — the single worst outcome available here.
///
/// Note what this is *not*: it is not the only thing keeping the mock away. This module builds
/// [`HttpScmdTransport`] unconditionally and never reads `cmd_transport` for anything else, so
/// there is no code path here that could select a mock even if this check were removed. The check
/// exists so the refusal is explicit and testable rather than merely true.
fn refuse_injected_transport(state: &AppState) -> Result<(), ApiError> {
    if state.cmd_transport.is_some() {
        return Err(ApiError::Conflict(
            "esta instância tem um transporte de Chave Móvel Digital injetado; uma assinatura de \
             teste de produção não corre contra um transporte simulado"
                .to_owned(),
        )
        .with_code(codes::SIMULATED_TRANSPORT));
    }
    Ok(())
}

// The deployment-level `require_production_environment` pre-check was REMOVED in t113.
//
// It read `settings.signing.cmd.env` and refused before the credential was even resolved, so an
// entry whose own `env` selector said `prod` was turned away on a deployment whose default was
// preprod — the defect this change exists to fix, and the one the operator was hitting. It was also
// a second source of truth for a question `resolve_cmd_env` now answers in exactly one place.
//
// Nothing is weakened by its removal: resolving the candidate is local and cheap, and the refusal
// that replaced it examines the config the signature would ACTUALLY use, which is strictly more
// accurate than the value the pre-check consulted. Both phases still refuse a non-production
// config before any SCMD call, and both still sit behind their own reauth + typed-phrase gate.

/// Where retained test signatures go, or a refusal. A server with no data directory keeps nothing,
/// and producing a real qualified signature that could not be retained is worse than not producing
/// one at all.
fn retention_dir(state: &AppState) -> Result<std::path::PathBuf, ApiError> {
    state
        .data_dir()
        .map(|dir| dir.join(RETENTION_DIR))
        .ok_or_else(|| {
            ApiError::Conflict(
            "esta instância não guarda ficheiros em disco, pelo que uma assinatura qualificada \
             real não poderia ser conservada; a assinatura de teste não foi iniciada"
                .to_owned(),
        )
            .with_code(codes::NO_RETENTION_STORAGE)
        })
}

// --- Credential resolution ---------------------------------------------------------------------

/// Resolve exactly one CMD credential candidate, pinned by `entry_id` when the caller named one.
///
/// Uses the signing path's own [`resolve_cmd_candidates`] walk, so precedence (stored entries in
/// priority order; the environment only when nothing is stored) and the fail-closed assembly of an
/// incomplete entry are the production behaviour, not a re-implementation of it. **No failover:**
/// this is a test of one credential, and quietly moving to the next one would answer the wrong
/// question with a real signature.
async fn resolve_pinned_candidate(
    state: &AppState,
    entry_id: Option<&str>,
) -> Result<(CmdConfig, ResolvedSource), ApiError> {
    let candidates = resolve_cmd_candidates(state).await?;
    if candidates.is_empty() {
        return Err(ApiError::Conflict(
            "a Chave Móvel Digital não está configurada: preencha application_id, \
             http_basic_username, http_basic_password e ama_cert_pem na credencial CMD do painel \
             de administração"
                .to_owned(),
        )
        .with_code(codes::CREDENTIALS_MISSING));
    }
    let chosen = match entry_id {
        Some(wanted) => candidates
            .into_iter()
            .find(|candidate| match &candidate.source {
                ResolvedSource::Stored { entry_id, .. } => entry_id == wanted,
                ResolvedSource::Env => false,
            })
            .ok_or_else(|| {
                ApiError::Conflict(
                    "a credencial indicada não existe ou está desativada; a assinatura de teste \
                     não recorre a outra credencial"
                        .to_owned(),
                )
                .with_code(codes::ENTRY_UNAVAILABLE)
            })?,
        None => candidates
            .into_iter()
            .next()
            .expect("the empty case returned above"),
    };
    Ok((chosen.config, chosen.source))
}

/// Non-secret provenance for the response and the audit payload.
fn describe_source(source: &ResolvedSource) -> (&'static str, Option<String>, Option<String>) {
    match source {
        ResolvedSource::Stored { entry_id, label } => {
            ("stored_entry", Some(entry_id.clone()), Some(label.clone()))
        }
        ResolvedSource::Env => ("environment", None, None),
    }
}

// --- SCMD drivers ------------------------------------------------------------------------------

/// `GetCertificate` → trusted-list gate → `CCMovelSign`, over a real [`HttpScmdTransport`].
///
/// There is deliberately no injected-transport branch. The act path's driver has one, because its
/// offline tests need it; this path must not, because a test signature is only meaningful when it
/// really reached AMA.
async fn run_test_initiate(
    state: &AppState,
    cfg: &CmdConfig,
    tsl_source: Option<crate::settings::RuntimeTslSource>,
    phone: &str,
    pin: &str,
    signing_time: OffsetDateTime,
    prepared: &PreparedSignature,
) -> Result<CmdSignSession, ApiError> {
    let policy_factory = state.cmd_trust_policy.clone();
    let cfg = cfg.clone();
    let prepared = prepared.clone();
    let phone = phone.to_owned();
    let pin = Zeroizing::new(pin.to_owned());
    tokio::task::spawn_blocking(move || {
        let transport = HttpScmdTransport::from_config(&cfg).map_err(cmd_config_err)?;
        let client = ScmdClient::from_config(transport, &cfg).map_err(cmd_config_err)?;
        let mut policy = build_trust_policy(policy_factory, tsl_source)?;
        let init = CmdInitiate {
            user_id: &phone,
            pin: &pin,
            doc_name: "chancela-teste-cmd.pdf",
            signing_time,
        };
        cmd_initiate(&client, &init, &prepared, Some(policy.as_mut())).map_err(map_signing_error)
    })
    .await
    .unwrap_or_else(|e| {
        Err(ApiError::Internal(format!(
            "cmd test initiate task failed: {e}"
        )))
    })
}

/// `ValidateOtp` → the detached CAdES-B CMS, over a real [`HttpScmdTransport`]. Same rule: no
/// injected-transport branch exists here.
async fn run_test_confirm(
    cfg: &CmdConfig,
    session: &CmdSignSession,
    otp: &str,
) -> Result<Vec<u8>, ApiError> {
    let cfg = cfg.clone();
    let session = session.clone();
    let otp = Zeroizing::new(otp.to_owned());
    tokio::task::spawn_blocking(move || {
        let transport = HttpScmdTransport::from_config(&cfg).map_err(cmd_config_err)?;
        let client = ScmdClient::from_config(transport, &cfg).map_err(cmd_config_err)?;
        cmd_confirm(&client, &session, &otp).map_err(map_signing_error)
    })
    .await
    .map_err(|e| ApiError::Internal(format!("cmd test confirm task failed: {e}")))?
}

// --- The document ------------------------------------------------------------------------------

/// The sheet the citizen's Chave Móvel Digital signs.
///
/// Its whole job is to be a document that describes itself. A qualified signature makes whatever
/// it covers evidentially strong, so the only safe thing to put under one in a connectivity test is
/// a statement of what the test was. Every fact here is server-held: the instance, the operator,
/// the moment, and which credential was exercised. Nothing comes from the request body.
///
/// Deterministic and pure — no clock, no randomness — so the same inputs render the same bytes.
pub fn build_cmd_test_document(
    instance_name: &str,
    actor_label: &str,
    generated_at: &str,
    credential_source: &str,
    entry_label: Option<&str>,
) -> DocumentModel {
    let mut blocks: Vec<Block> = vec![
        emphatic(
            "Este documento é um teste de ligação à Chave Móvel Digital. Não é uma ata, não é um termo \
             e não constitui um registo da atividade da organização.",
        ),
        plain(
            "Foi gerado pela aplicação, no momento indicado abaixo, para verificar que a integração \
             com a Chave Móvel Digital funciona em produção. O seu conteúdo é o que aqui está escrito \
             e nada mais.",
        ),
        Block::Rule,
        Block::Heading {
            level: 2,
            text: "Identificação do teste".to_owned(),
        },
    ];
    let mut rows = vec![
        kv("Instância", instance_name),
        kv("Operador que pediu o teste", actor_label),
        kv("Momento em que foi gerado", generated_at),
        kv(
            "Origem das credenciais",
            match credential_source {
                "stored_entry" => "Credencial guardada no painel de administração",
                _ => "Variáveis de ambiente do servidor",
            },
        ),
    ];
    // Absent means absent: no row rather than an empty one, and never an invented value.
    if let Some(label) = entry_label {
        rows.push(kv("Credencial utilizada", label));
    }
    rows.push(kv("Ambiente", "Produção"));
    blocks.push(Block::KeyValue { rows });

    blocks.push(Block::Heading {
        level: 2,
        text: "O que esta assinatura é e o que não é".to_owned(),
    });
    blocks.push(emphatic(
        "A assinatura aposta neste documento é uma assinatura eletrónica qualificada real, feita \
         com a Chave Móvel Digital do próprio signatário.",
    ));
    blocks.push(plain(
        "É real porque a Chave Móvel Digital não tem outro modo de funcionamento: não existe \
         ensaio nem simulação. O signatário recebeu um código por mensagem e introduziu o seu PIN, \
         tal como faria ao assinar qualquer outro documento.",
    ));
    blocks.push(plain(
        "O que a assinatura cobre é apenas este documento. Não abre nem encerra livro algum, não \
         assina ata alguma e não conta para qualquer assinatura exigida por um livro ou por um \
         termo. A aplicação conserva-o como prova de que o teste foi feito e de quem o pediu.",
    ));
    blocks.push(Block::Rule);
    blocks.push(plain(
        "Conservado em registo próprio, separado dos documentos da organização.",
    ));

    let mut model = DocumentModel::new(
        "Documento de teste da Chave Móvel Digital",
        instance_name,
        "Teste de ligação à Chave Móvel Digital em produção",
    );
    model.created_at = Some(generated_at.to_owned());
    model.blocks = blocks;
    model
}

fn kv(key: impl Into<String>, value: impl Into<String>) -> KvRow {
    KvRow {
        key: key.into(),
        value: value.into(),
    }
}

fn plain(text: impl Into<String>) -> Block {
    Block::Paragraph {
        runs: vec![Run {
            text: text.into(),
            bold: false,
            italic: false,
        }],
    }
}

fn emphatic(text: impl Into<String>) -> Block {
    Block::Paragraph {
        runs: vec![Run {
            text: text.into(),
            bold: true,
            italic: false,
        }],
    }
}

// --- Retention and audit -----------------------------------------------------------------------

/// Write the signed PDF and its non-secret sidecar. Retention failure is an error, not a warning:
/// the signature already exists, and silently losing it is exactly the evidentiary failure this
/// repo forbids.
fn retain_test_signature(
    dir: &std::path::Path,
    record: &RetainedTestSignature,
    signed_pdf: &[u8],
) -> Result<(), ApiError> {
    std::fs::create_dir_all(dir).map_err(|e| {
        ApiError::Internal(format!(
            "a assinatura de teste foi produzida mas a pasta de conservação não pôde ser criada: {e}"
        ))
    })?;
    std::fs::write(dir.join(format!("{}.pdf", record.test_id)), signed_pdf).map_err(|e| {
        ApiError::Internal(format!(
            "a assinatura de teste foi produzida mas não pôde ser conservada: {e}"
        ))
    })?;
    let sidecar = serde_json::to_vec_pretty(record)?;
    std::fs::write(dir.join(format!("{}.json", record.test_id)), sidecar).map_err(|e| {
        ApiError::Internal(format!(
            "a assinatura de teste foi conservada mas o seu registo não pôde ser escrito: {e}"
        ))
    })?;
    Ok(())
}

/// Append one audit event under this module's own scope. Chain-safe and durable: a failure here
/// fails the request, which is what makes "intent recorded before AMA is contacted" a real
/// guarantee rather than a best effort.
async fn record_audit(
    state: &AppState,
    actor_label: &str,
    attestor: &CurrentAttestor,
    kind: &str,
    payload: serde_json::Value,
) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(&payload)?;
    let mut ledger = state.ledger.write().await;
    crate::try_append_event(&mut ledger, actor_label, AUDIT_SCOPE, kind, None, &bytes)?;
    state
        .persist_write_through(&mut ledger, 1, |_tx| Ok(()))
        .await?;
    state.attest_latest(attestor, &ledger).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document_text(model: &DocumentModel) -> String {
        let mut out = String::new();
        for block in &model.blocks {
            match block {
                Block::Heading { text, .. } => out.push_str(text),
                Block::Paragraph { runs } => {
                    for run in runs {
                        out.push_str(&run.text);
                    }
                }
                Block::KeyValue { rows } => {
                    for row in rows {
                        out.push_str(&row.key);
                        out.push_str(&row.value);
                    }
                }
                _ => {}
            }
            out.push('\n');
        }
        out
    }

    /// The document's whole safety argument is that it describes itself. If these sentences ever
    /// leave it, a real qualified signature would be sitting on a sheet that does not say what it
    /// is — which is the failure mode the whole feature is shaped around avoiding.
    #[test]
    fn the_test_document_states_plainly_what_it_is_and_what_it_is_not() {
        let model = build_cmd_test_document(
            "Encosto Estratégico Lda",
            "amelia.marques",
            "2026-07-27T10:15:00Z",
            "stored_entry",
            Some("CMD principal"),
        );
        let text = document_text(&model);

        assert!(text.contains("teste de ligação à Chave Móvel Digital"));
        assert!(text.contains("Não é uma ata, não é um termo"));
        assert!(text.contains("assinatura eletrónica qualificada real"));
        assert!(text.contains("Não abre nem encerra livro algum"));
        assert!(text.contains("não conta para qualquer assinatura exigida"));

        // The four server-held facts that make the sheet identifiable after the fact.
        assert!(text.contains("Encosto Estratégico Lda"));
        assert!(text.contains("amelia.marques"));
        assert!(text.contains("2026-07-27T10:15:00Z"));
        assert!(text.contains("CMD principal"));

        // The repo's standing copy rule: this phrase never appears in operator-facing text.
        assert!(!text.contains("valor probatório"));
    }

    /// Absent means absent. With no stored entry there is no credential label, and the document
    /// omits the row rather than printing an empty one or inventing a placeholder.
    #[test]
    fn an_absent_credential_label_produces_no_row_rather_than_an_empty_one() {
        let model = build_cmd_test_document(
            "Encosto Estratégico Lda",
            "amelia.marques",
            "2026-07-27T10:15:00Z",
            "environment",
            None,
        );
        let rows: Vec<&KvRow> = model
            .blocks
            .iter()
            .filter_map(|block| match block {
                Block::KeyValue { rows } => Some(rows),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(
            rows.iter().all(|row| row.key != "Credencial utilizada"),
            "no stored entry means no credential-label row at all"
        );
        assert!(
            rows.iter().all(|row| !row.value.trim().is_empty()),
            "no row may render with an empty value"
        );
        assert!(
            rows.iter()
                .any(|row| row.value.contains("Variáveis de ambiente")),
            "the environment fallback is named honestly as the credential source"
        );
    }

    /// The document must actually render, and the rendered bytes must be preparable for PAdES.
    ///
    /// This is the one part of the signing pipeline that can be proven offline: everything up to
    /// and including the ByteRange digest is local. Proving it here means a production test
    /// signature cannot fail *after* the OTP has been dispatched because the document was
    /// unrenderable — the citizen would have been asked to authorize a signature that could never
    /// complete.
    #[test]
    fn the_test_document_renders_and_can_be_prepared_for_signature() {
        let model = build_cmd_test_document(
            "Encosto Estratégico Lda",
            "amelia.marques",
            "2026-07-27T10:15:00Z",
            "stored_entry",
            Some("CMD principal"),
        );
        let bytes = chancela_doc::pdfa::write(&model).expect("the test document renders as PDF/A");
        let opts = SignOptions {
            field_name: Some("Assinatura".to_owned()),
            signing_time: None,
            reason: Some("Teste".to_owned()),
            location: None,
            contact_info: None,
        };
        let prepared =
            prepare_signature(&bytes, &opts).expect("the rendered document prepares for PAdES");
        assert!(
            !prepared.byterange_digest().is_empty(),
            "a prepared revision carries the digest CMD would sign"
        );
    }

    /// The self-validation must report a bad answer rather than no answer.
    ///
    /// The success path needs a real qualified signature and cannot be reached offline, but the
    /// branch that matters most for honesty can: bytes the validator refuses must come back as an
    /// explicit negative verdict carrying the reason, not as an absence, not as a default `true`,
    /// and never as an error that would replace a retained real signature with a 500.
    #[test]
    fn bytes_the_validator_refuses_produce_an_explicit_negative_verdict() {
        let model = build_cmd_test_document(
            "Encosto Estratégico Lda",
            "amelia.marques",
            "2026-07-27T10:15:00Z",
            "stored_entry",
            Some("CMD principal"),
        );
        // A rendered but UNSIGNED PDF/A: well-formed PDF, no signature dictionary. This is exactly
        // the shape a broken embed step would leave behind, and it must not read as verified.
        let unsigned = chancela_doc::pdfa::write(&model).expect("the test document renders");

        let verdict = self_validate(&unsigned);

        assert!(!verdict.signature_verifies);
        assert!(!verdict.covers_rendered_document);
        assert_eq!(verdict.coverage, "unavailable");
        assert!(!verdict.signature_timestamp_present);
        assert!(
            verdict.error.is_some(),
            "a verdict of `unavailable` must say why"
        );

        // The negative verdict has to survive serialization as VALUES: a client that received an
        // object with the flags omitted could read the silence as a pass.
        let json = serde_json::to_value(&verdict).expect("the verdict serializes");
        assert_eq!(json["signature_verifies"], serde_json::json!(false));
        assert_eq!(json["covers_rendered_document"], serde_json::json!(false));
        assert_eq!(json["coverage"], serde_json::json!("unavailable"));
    }

    /// The initiate response states the **PIN-accepted checkpoint as a value**, alongside the
    /// unchanged honesty flags.
    ///
    /// The initiate happy path cannot be reached offline — it contacts AMA — so the response *shape*
    /// is what is pinned here: `pin_accepted` is a boolean a client can read, not an omission it must
    /// infer from the flow having advanced. It coexists with the safety markers being exactly what
    /// they were: the provider was contacted and an OTP dispatched, and NOTHING is signed at the
    /// initiate phase. Making the PIN result legible does not add a way to sign.
    #[test]
    fn the_initiate_response_states_pin_accepted_as_a_value_with_the_honesty_flags_intact() {
        let resp = CmdTestSignatureInitiateResponse {
            session_id: "sess".to_owned(),
            status: "otp_pending",
            masked_phone: "+351 9*****678".to_owned(),
            credential_source: "stored_entry",
            entry_id: Some("cmd-entry-1".to_owned()),
            entry_label: Some("CMD principal".to_owned()),
            environment: "prod",
            expires_at: "2026-07-27T10:20:00Z".to_owned(),
            pin_accepted: true,
            provider_contacted: true,
            signer_authorization_requested: true,
            document_signed: false,
        };
        let json = serde_json::to_value(&resp).expect("the initiate response serializes");

        // The checkpoint is present as a VALUE the client reads, not an absence it interprets.
        assert_eq!(json["pin_accepted"], serde_json::json!(true));
        // The safety markers are unchanged: contacted and OTP-dispatched, but nothing signed yet.
        assert_eq!(json["provider_contacted"], serde_json::json!(true));
        assert_eq!(
            json["signer_authorization_requested"],
            serde_json::json!(true)
        );
        assert_eq!(json["document_signed"], serde_json::json!(false));
    }

    /// Garbage that is not a PDF at all takes the same honest branch — the validator's refusal is
    /// reported, and nothing panics or unwraps its way out of a real signature's result.
    #[test]
    fn non_pdf_bytes_are_a_verdict_and_not_a_panic() {
        let verdict = self_validate(b"this is not a PDF");
        assert!(!verdict.signature_verifies);
        assert_eq!(verdict.coverage, "unavailable");
        assert!(verdict.error.is_some());
    }
}
